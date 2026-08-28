#!/usr/bin/env python3
"""A deliberately local PKCS#1 v1.5 padding-oracle research fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import secrets
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Callable, Iterable


MIN_RSA_BITS = 256
MAX_RSA_BITS = 512
MIN_QUERY_BUDGET = 10_000
MAX_QUERY_BUDGET = 20_000_000
MIN_TIME_BUDGET = 5.0
MAX_TIME_BUDGET = 300.0

SMALL_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)


class AttackError(RuntimeError):
    pass


class BudgetExceeded(AttackError):
    pass


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class CRTPrivateKey:
    n: int
    p: int
    q: int
    dp: int
    dq: int
    q_inverse: int

    def private_operation(self, value: int) -> int:
        # q_inverse is q^-1 mod p. Keeping this operation here makes the
        # oracle cheap without putting any private material in the attacker.
        mod_p = pow(value, self.dp, self.p)
        mod_q = pow(value, self.dq, self.q)
        correction = ((mod_p - mod_q) * self.q_inverse) % self.p
        return mod_q + correction * self.q


@dataclass(frozen=True)
class AttackResult:
    encoded_message: bytes
    blinding_multiplier: int
    rounds: int
    queries: int
    accepting_queries: int
    peak_intervals: int
    elapsed_seconds: float
    phase_queries: dict[str, int]


def ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


def miller_rabin(candidate: int, rounds: int = 24) -> bool:
    if candidate in (2, 3):
        return True
    if candidate < 2 or candidate & 1 == 0:
        return False

    for prime in SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    odd_part = candidate - 1
    twos = 0
    while odd_part & 1 == 0:
        twos += 1
        odd_part >>= 1

    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        witness = pow(base, odd_part, candidate)
        if witness in (1, candidate - 1):
            continue
        for _ in range(twos - 1):
            witness = witness * witness % candidate
            if witness == candidate - 1:
                break
        else:
            return False
    return True


def probable_prime(bits: int, exponent: int) -> int:
    if bits < 16:
        raise ValueError("prime size is too small")

    high_bits = (1 << (bits - 1)) | (1 << (bits - 2))
    while True:
        candidate = secrets.randbits(bits) | high_bits | 1
        if math.gcd(candidate - 1, exponent) != 1:
            continue
        if miller_rabin(candidate):
            return candidate


def generate_keypair(bits: int, exponent: int = 65537) -> tuple[PublicKey, CRTPrivateKey]:
    left_bits = bits // 2
    right_bits = bits - left_bits

    while True:
        p = probable_prime(left_bits, exponent)
        q = probable_prime(right_bits, exponent)
        if p == q:
            continue

        n = p * q
        if n.bit_length() != bits:
            continue

        carmichael = math.lcm(p - 1, q - 1)
        private_exponent = pow(exponent, -1, carmichael)
        public = PublicKey(n=n, e=exponent)
        private = CRTPrivateKey(
            n=n,
            p=p,
            q=q,
            dp=private_exponent % (p - 1),
            dq=private_exponent % (q - 1),
            q_inverse=pow(q, -1, p),
        )
        return public, private


def nonzero_random(length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        output.extend(byte for byte in secrets.token_bytes(length - len(output)) if byte)
    return bytes(output)


def encode_pkcs1_v1_5(message: bytes, size: int) -> bytes:
    padding_length = size - len(message) - 3
    if padding_length < 8:
        raise ValueError(f"message is {len(message)} bytes; maximum for this key is {size - 11}")
    return b"\x00\x02" + nonzero_random(padding_length) + b"\x00" + message


def decode_pkcs1_v1_5(block: bytes) -> bytes | None:
    if len(block) < 11 or block[:2] != b"\x00\x02":
        return None
    separator = block.find(b"\x00", 2)
    if separator < 10:
        return None
    return block[separator + 1 :]


class LocalPaddingOracle:
    """The vulnerable side of the lab. Its only public leak is one boolean."""

    __slots__ = ("_private", "_size", "_boundary", "queries", "accepts")

    def __init__(self, private_key: CRTPrivateKey, size: int):
        self._private = private_key
        self._size = size
        self._boundary = 1 << (8 * (size - 2))
        self.queries = 0
        self.accepts = 0

    def query(self, ciphertext: int) -> bool:
        self.queries += 1
        if not 0 <= ciphertext < self._private.n:
            return False

        plaintext = self._private.private_operation(ciphertext)
        if not 2 * self._boundary <= plaintext < 3 * self._boundary:
            return False
        block = plaintext.to_bytes(self._size, "big")
        conforming = decode_pkcs1_v1_5(block) is not None
        self.accepts += int(conforming)
        return conforming


class MeteredOracle:
    __slots__ = (
        "_oracle",
        "_budget",
        "_deadline",
        "_progress_every",
        "_progress",
        "queries",
        "accepts",
        "phases",
        "started",
    )

    def __init__(
        self,
        oracle: Callable[[int], bool],
        query_budget: int,
        time_budget: float,
        progress_every: int,
        progress: Callable[[int, float, str], None] | None,
    ):
        self._oracle = oracle
        self._budget = query_budget
        self.started = time.perf_counter()
        self._deadline = self.started + time_budget
        self._progress_every = progress_every
        self._progress = progress
        self.queries = 0
        self.accepts = 0
        self.phases: Counter[str] = Counter()

    def ask(self, ciphertext: int, phase: str) -> bool:
        if self.queries >= self._budget:
            raise BudgetExceeded(f"oracle query budget exhausted at {self.queries:,}")
        if time.perf_counter() >= self._deadline:
            raise BudgetExceeded(f"attack time budget exhausted at {self.queries:,} queries")

        answer = bool(self._oracle(ciphertext))
        self.queries += 1
        self.accepts += int(answer)
        self.phases[phase] += 1

        if (
            self._progress is not None
            and self._progress_every
            and self.queries % self._progress_every == 0
        ):
            self._progress(self.queries, time.perf_counter() - self.started, phase)
        return answer


def merge_intervals(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted(intervals)
    if not ordered:
        return []

    merged = [ordered[0]]
    for lower, upper in ordered[1:]:
        old_lower, old_upper = merged[-1]
        if lower <= old_upper + 1:
            merged[-1] = (old_lower, max(old_upper, upper))
        else:
            merged.append((lower, upper))
    return merged


def refine_intervals(
    intervals: list[tuple[int, int]],
    multiplier: int,
    modulus: int,
    boundary: int,
) -> list[tuple[int, int]]:
    next_intervals: list[tuple[int, int]] = []
    lower_band = 2 * boundary
    upper_band = 3 * boundary - 1

    for lower, upper in intervals:
        r_min = ceil_div(lower * multiplier - upper_band, modulus)
        r_max = (upper * multiplier - lower_band) // modulus
        for quotient in range(r_min, r_max + 1):
            narrowed_lower = max(lower, ceil_div(lower_band + quotient * modulus, multiplier))
            narrowed_upper = min(upper, (upper_band + quotient * modulus) // multiplier)
            if narrowed_lower <= narrowed_upper:
                next_intervals.append((narrowed_lower, narrowed_upper))

    return merge_intervals(next_intervals)


def recover_pkcs1_block(
    public_key: PublicKey,
    ciphertext: int,
    oracle: Callable[[int], bool],
    *,
    query_budget: int,
    time_budget: float,
    progress_every: int = 0,
    progress: Callable[[int, float, str], None] | None = None,
) -> AttackResult:
    """Recover a block using only (n, e), ciphertext, and an oracle callback."""

    n, e = public_key.n, public_key.e
    size = public_key.size_bytes
    if size < 11:
        raise AttackError("modulus is too small for PKCS#1 v1.5 encryption")
    if not 0 <= ciphertext < n:
        raise AttackError("ciphertext is outside the RSA residue set")

    boundary = 1 << (8 * (size - 2))
    lower_band = 2 * boundary
    upper_band = 3 * boundary - 1
    probe = MeteredOracle(oracle, query_budget, time_budget, progress_every, progress)

    if probe.ask(ciphertext, "blinding"):
        blinding_multiplier = 1
        working_ciphertext = ciphertext
    else:
        blinding_multiplier = 2
        while True:
            if math.gcd(blinding_multiplier, n) == 1:
                blinded = ciphertext * pow(blinding_multiplier, e, n) % n
                if probe.ask(blinded, "blinding"):
                    working_ciphertext = blinded
                    break
            blinding_multiplier += 1

    intervals = [(lower_band, upper_band)]
    multiplier = ceil_div(n, 3 * boundary)
    while True:
        candidate = working_ciphertext * pow(multiplier, e, n) % n
        if probe.ask(candidate, "initial search"):
            break
        multiplier += 1

    rounds = 1
    intervals = refine_intervals(intervals, multiplier, n, boundary)
    if not intervals:
        raise AttackError("oracle response produced an empty interval set")
    peak_intervals = len(intervals)

    while len(intervals) != 1 or intervals[0][0] != intervals[0][1]:
        if rounds > n.bit_length() * 4:
            raise AttackError("interval narrowing failed to converge")

        if len(intervals) > 1:
            multiplier += 1
            while True:
                candidate = working_ciphertext * pow(multiplier, e, n) % n
                if probe.ask(candidate, "multi-interval search"):
                    break
                multiplier += 1
        else:
            lower, upper = intervals[0]
            quotient = ceil_div(2 * (upper * multiplier - lower_band), n)
            found = False
            while not found:
                start = ceil_div(lower_band + quotient * n, upper)
                stop = (upper_band + quotient * n) // lower
                for next_multiplier in range(start, stop + 1):
                    candidate = working_ciphertext * pow(next_multiplier, e, n) % n
                    if probe.ask(candidate, "single-interval search"):
                        multiplier = next_multiplier
                        found = True
                        break
                quotient += 1

        intervals = refine_intervals(intervals, multiplier, n, boundary)
        if not intervals:
            raise AttackError("oracle response produced an empty interval set")
        peak_intervals = max(peak_intervals, len(intervals))
        rounds += 1

    blinded_plaintext = intervals[0][0]
    try:
        inverse = pow(blinding_multiplier, -1, n)
    except ValueError as exc:
        raise AttackError("blinding multiplier was not invertible") from exc
    plaintext = blinded_plaintext * inverse % n
    encoded = plaintext.to_bytes(size, "big")

    return AttackResult(
        encoded_message=encoded,
        blinding_multiplier=blinding_multiplier,
        rounds=rounds,
        queries=probe.queries,
        accepting_queries=probe.accepts,
        peak_intervals=peak_intervals,
        elapsed_seconds=time.perf_counter() - probe.started,
        phase_queries=dict(probe.phases),
    )


def malformed_blocks(size: int) -> dict[str, bytes]:
    return {
        "wrong block type": b"\x00\x01" + b"\xff" * (size - 3) + b"\x00",
        "seven-byte PS": b"\x00\x02" + b"\xa5" * 7 + b"\x00" + b"x" * (size - 10),
        "early zero in PS": b"\x00\x02abc\x00" + b"z" * (size - 6),
        "missing separator": b"\x00\x02" + b"\xa5" * (size - 2),
    }


def run_negative_controls(public_key: PublicKey, oracle: LocalPaddingOracle) -> list[str]:
    rejected: list[str] = []
    for name, block in malformed_blocks(public_key.size_bytes).items():
        if len(block) != public_key.size_bytes:
            raise AssertionError(f"negative control {name!r} has the wrong length")
        if decode_pkcs1_v1_5(block) is not None:
            raise AssertionError(f"strict decoder accepted {name}")
        raw = int.from_bytes(block, "big")
        if raw >= public_key.n:
            raise AssertionError(f"negative control {name!r} is outside the modulus")
        if oracle.query(pow(raw, public_key.e, public_key.n)):
            raise AssertionError(f"oracle accepted {name}")
        rejected.append(name)

    if oracle.query(0):
        raise AssertionError("oracle accepted the zero ciphertext")
    rejected.append("zero ciphertext")
    return rejected


def bounded_int(label: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value.replace("_", ""), 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{label} must be an integer") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"{label} must be between {minimum:,} and {maximum:,}")
        return parsed

    return parse


def bounded_float(label: str, minimum: float, maximum: float) -> Callable[[str], float]:
    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{label} must be a number") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"{label} must be between {minimum:g} and {maximum:g}")
        return parsed

    return parse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="run a self-contained adaptive RSA PKCS#1 v1.5 padding-oracle lab",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--run-local-lab",
        action="store_true",
        help="required acknowledgement; the script has no remote-target mode",
    )
    parser.add_argument(
        "--bits",
        type=bounded_int("bits", MIN_RSA_BITS, MAX_RSA_BITS),
        default=256,
        help=f"generated RSA modulus size ({MIN_RSA_BITS}..{MAX_RSA_BITS}, default: 256)",
    )
    parser.add_argument(
        "--exponent",
        type=int,
        choices=(3, 65537),
        default=3,
        help="RSA public exponent; 3 keeps the pure-Python lab responsive (default: 3)",
    )
    parser.add_argument(
        "--message",
        default="local oracle proof",
        help="UTF-8 plaintext placed in the generated challenge",
    )
    parser.add_argument(
        "--query-budget",
        type=bounded_int("query budget", MIN_QUERY_BUDGET, MAX_QUERY_BUDGET),
        default=5_000_000,
        help="hard attack-query ceiling; controls run afterward (default: 5,000,000)",
    )
    parser.add_argument(
        "--time-budget",
        type=bounded_float("time budget", MIN_TIME_BUDGET, MAX_TIME_BUDGET),
        default=180.0,
        help="hard attack-time ceiling in seconds (default: 180)",
    )
    parser.add_argument(
        "--progress-every",
        type=bounded_int("progress interval", 10_000, 5_000_000),
        default=250_000,
        help="emit one progress line per N oracle queries (default: 250,000)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress periodic progress")
    parser.add_argument("--json", action="store_true", help="emit the final report as JSON")
    args = parser.parse_args(argv)

    if not args.run_local_lab:
        parser.error("refusing to run without --run-local-lab")
    if args.bits % 8:
        parser.error("--bits must be a multiple of 8")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    message = args.message.encode("utf-8")

    key_started = time.perf_counter()
    public, private = generate_keypair(args.bits, args.exponent)
    key_seconds = time.perf_counter() - key_started
    size = public.size_bytes
    if len(message) > size - 11:
        raise SystemExit(
            f"message is {len(message)} UTF-8 bytes; a {args.bits}-bit key allows at most {size - 11}"
        )

    encoded = encode_pkcs1_v1_5(message, size)
    plaintext_integer = int.from_bytes(encoded, "big")
    ciphertext = pow(plaintext_integer, public.e, public.n)
    oracle = LocalPaddingOracle(private, size)

    def progress(queries: int, elapsed: float, phase: str) -> None:
        print(
            f"[attack] {queries:>10,} queries  {elapsed:>7.2f}s  {phase}",
            file=sys.stderr,
            flush=True,
        )

    result = recover_pkcs1_block(
        public,
        ciphertext,
        oracle.query,
        query_budget=args.query_budget,
        time_budget=args.time_budget,
        progress_every=0 if args.quiet else args.progress_every,
        progress=None if args.quiet else progress,
    )

    recovered_message = decode_pkcs1_v1_5(result.encoded_message)
    if result.encoded_message != encoded:
        raise AttackError("recovered integer does not match the original encoded block")
    if recovered_message != message:
        raise AttackError("recovered application plaintext does not match exactly")

    controls = run_negative_controls(public, oracle)
    report = {
        "lab_only": True,
        "rsa_bits": public.n.bit_length(),
        "public_exponent": public.e,
        "key_generation_seconds": round(key_seconds, 6),
        "ciphertext_sha256": hashlib.sha256(ciphertext.to_bytes(size, "big")).hexdigest(),
        "encoded_block_sha256": hashlib.sha256(encoded).hexdigest(),
        "message_utf8": recovered_message.decode("utf-8"),
        "exact_block_match": result.encoded_message == encoded,
        "exact_message_match": recovered_message == message,
        "attack": {
            **{key: value for key, value in asdict(result).items() if key != "encoded_message"},
            "elapsed_seconds": round(result.elapsed_seconds, 6),
            "queries_per_second": round(result.queries / result.elapsed_seconds, 2),
        },
        "negative_controls_rejected": controls,
        "oracle_total_queries_including_controls": oracle.queries,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"RSA modulus          {report['rsa_bits']} bits, e={public.e}")
        print(f"key generation       {key_seconds:.3f}s")
        print(f"ciphertext sha256     {report['ciphertext_sha256']}")
        print(f"recovered plaintext   {recovered_message!r}")
        print(f"exact block match     {report['exact_block_match']}")
        print(f"attack rounds         {result.rounds:,}")
        print(f"oracle queries        {result.queries:,} ({result.accepting_queries:,} accepted)")
        print(f"attack time           {result.elapsed_seconds:.3f}s")
        print(f"query rate            {report['attack']['queries_per_second']:,.0f}/s")
        for phase, count in result.phase_queries.items():
            print(f"  {phase:<24} {count:>10,}")
        print(f"negative controls     {len(controls)} rejected: {', '.join(controls)}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AttackError, ValueError) as error:
        print(f"oraclestrike: {error}", file=sys.stderr)
        raise SystemExit(1) from error
