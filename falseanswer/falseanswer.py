#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import queue
import secrets
import socket
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass, replace

LOOPBACK = "127.0.0.1"
AUTHORITY_IP = "127.0.0.2"
ATTACKER_IP = "127.0.0.3"

PROBE_NAME = "state.attacker.test"
TARGET_NAME = "archive.service.test"
PROBE_IP = "198.51.100.53"
LEGITIMATE_IP = "192.0.2.44"
POISONED_IP = "203.0.113.66"

DNS_HEADER = struct.Struct("!HHHHHH")
QUESTION_TAIL = struct.Struct("!HH")
RR_HEADER = struct.Struct("!HHIH")

TYPE_A = 1
CLASS_IN = 1
FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080
OPCODE_MASK = 0x7800
RCODE_MASK = 0x000F
RESERVED_MASK = 0x0070
MAX_PACKET = 1232
MAX_TTL = 300

LCG_MULTIPLIER = 25173
LCG_INCREMENT = 13849
FORGED_BURST_WAVES = 4
FORGED_PACKETS_PER_WAVE = 16
FORGED_WAVE_PAUSE = 0.005
ATTACK_AFTER_INDUCTION_SECONDS = 0.050
MAX_SCENARIO_ATTEMPTS = 5


class LabError(RuntimeError):
    pass


class DnsError(ValueError):
    pass


class ScenarioInconclusive(RuntimeError):
    pass


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class QueryObservation:
    txid: int
    source_ip: str
    source_port: int
    name: str


@dataclass(frozen=True)
class ResolutionTrace:
    name: str
    cache_hit: bool
    upstream_txid: int | None
    upstream_port: int | None
    accepted_source: str | None
    upstream_send_completed_ns: int | None
    response_accepted_ns: int | None


@dataclass(frozen=True)
class ExchangeResult:
    address: str
    ttl: int
    txid: int
    source_port: int
    accepted_source: str
    upstream_send_completed_ns: int
    response_accepted_ns: int


@dataclass(frozen=True)
class BurstEvidence:
    packets_sent: int
    first_send_started_ns: int
    last_send_completed_ns: int


@dataclass(frozen=True)
class ModePolicy:
    random_txid: bool
    random_port: bool
    strict_source: bool


MODE_POLICIES = {
    "vulnerable": ModePolicy(False, False, False),
    "random_txid": ModePolicy(True, False, False),
    "random_port": ModePolicy(False, True, False),
    "strict_source": ModePolicy(False, False, True),
    "fixed": ModePolicy(True, True, True),
}
MODE_ORDER = tuple(MODE_POLICIES)


@dataclass(frozen=True)
class ScenarioResult:
    mode: str
    policy: ModePolicy
    attempts: int
    inconclusive_retries: int
    retry_reasons: list[str]
    observed_txid: int
    predicted_txid: int
    observed_upstream_port: int
    target_txid: int
    target_upstream_port: int
    prediction_matched: bool
    port_reused: bool
    induction_send_completed_ns: int
    target_upstream_send_completed_ns: int
    first_forged_send_started_ns: int
    last_forged_send_completed_ns: int
    accepted_response_ns: int
    forge_after_upstream_us: int
    timing_order_verified: bool
    forged_packets_sent: int
    forged_outcome: str
    accepted_source: str
    first_answer: str
    second_answer: str
    authority_queries: int
    cache_hits: int
    rejected_datagrams: int
    rejection_reasons: dict[str, int]


def validate_label(label: str) -> None:
    if not 1 <= len(label) <= 63:
        raise DnsError("DNS label length is outside 1..63")
    if (
        label[0] == "-"
        or label[-1] == "-"
        or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in label)
    ):
        raise DnsError(f"invalid lab DNS label: {label!r}")


def canonical_name(name: str) -> str:
    value = name.rstrip(".").lower()
    if not value:
        raise DnsError("the root name is not used by this lab")
    labels = value.split(".")
    wire_length = 1
    for label in labels:
        try:
            encoded = label.encode("ascii", "strict")
        except UnicodeEncodeError as exc:
            raise DnsError("DNS labels must be ASCII") from exc
        validate_label(label)
        wire_length += 1 + len(encoded)
    if wire_length > 255:
        raise DnsError("encoded DNS name exceeds 255 bytes")
    return value


def encode_name(name: str) -> bytes:
    labels = canonical_name(name).split(".")
    return (
        b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels)
        + b"\0"
    )


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(packet):
        raise DnsError("DNS name starts outside the packet")

    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    pointer_targets: set[int] = set()
    expanded_length = 1

    for _hop in range(128):
        if cursor >= len(packet):
            raise DnsError("truncated DNS name")
        length = packet[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= cursor:
                raise DnsError("forward DNS compression pointer")
            if pointer in pointer_targets:
                raise DnsError("DNS compression pointer loop")
            pointer_targets.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise DnsError("reserved DNS label encoding")

        cursor += 1
        if length == 0:
            if next_offset is None:
                next_offset = cursor
            break
        if length > 63 or cursor + length > len(packet):
            raise DnsError("truncated or oversized DNS label")

        raw_label = packet[cursor : cursor + length]
        try:
            label = raw_label.decode("ascii", "strict").lower()
        except UnicodeDecodeError as exc:
            raise DnsError("non-ASCII DNS label") from exc
        validate_label(label)
        labels.append(label)
        expanded_length += length + 1
        if expanded_length > 255:
            raise DnsError("expanded DNS name exceeds 255 bytes")
        cursor += length
    else:
        raise DnsError("excessive DNS compression indirection")

    if not labels or next_offset is None:
        raise DnsError("empty DNS name")
    return ".".join(labels), next_offset


def unpack_header(packet: bytes) -> tuple[int, int, int, int, int, int]:
    if len(packet) < DNS_HEADER.size:
        raise DnsError("truncated DNS header")
    return DNS_HEADER.unpack_from(packet)


def parse_query(packet: bytes) -> tuple[int, Question, bool]:
    txid, flags, qdcount, ancount, nscount, arcount = unpack_header(packet)
    if flags & ~FLAG_RD:
        raise DnsError("unsupported query flags")
    if qdcount != 1 or ancount or nscount or arcount:
        raise DnsError("query must contain exactly one question")

    name, offset = decode_name(packet, DNS_HEADER.size)
    if offset + QUESTION_TAIL.size != len(packet):
        raise DnsError("query has trailing or truncated fields")
    qtype, qclass = QUESTION_TAIL.unpack_from(packet, offset)
    if qtype != TYPE_A or qclass != CLASS_IN:
        raise DnsError("only IN A questions are supported")
    return txid, Question(name, qtype, qclass), bool(flags & FLAG_RD)


def parse_a_response(
    packet: bytes,
    expected_txid: int,
    expected_question: Question,
    *,
    require_authoritative: bool,
) -> tuple[str, int]:
    txid, flags, qdcount, ancount, nscount, arcount = unpack_header(packet)
    if txid != expected_txid:
        raise DnsError("transaction ID mismatch")
    if not flags & FLAG_QR or flags & (
        OPCODE_MASK | FLAG_TC | RESERVED_MASK | RCODE_MASK
    ):
        raise DnsError("invalid response flags")
    if require_authoritative and not flags & FLAG_AA:
        raise DnsError("upstream answer is not authoritative")
    if qdcount != 1 or ancount != 1 or nscount or arcount:
        raise DnsError("response must contain one question and one answer")

    name, offset = decode_name(packet, DNS_HEADER.size)
    if offset + QUESTION_TAIL.size > len(packet):
        raise DnsError("truncated response question")
    qtype, qclass = QUESTION_TAIL.unpack_from(packet, offset)
    question = Question(name, qtype, qclass)
    if question != expected_question:
        raise DnsError("response question mismatch")
    offset += QUESTION_TAIL.size

    owner, offset = decode_name(packet, offset)
    if offset + RR_HEADER.size > len(packet):
        raise DnsError("truncated answer header")
    rr_type, rr_class, ttl, rdlength = RR_HEADER.unpack_from(packet, offset)
    offset += RR_HEADER.size
    if owner != expected_question.name or rr_type != TYPE_A or rr_class != CLASS_IN:
        raise DnsError("unexpected answer owner or type")
    if rdlength != 4 or offset + rdlength != len(packet):
        raise DnsError("invalid A record length or trailing bytes")
    if not 1 <= ttl <= MAX_TTL:
        raise DnsError("answer TTL is outside the lab policy")
    return socket.inet_ntoa(packet[offset : offset + 4]), ttl


def build_query(txid: int, name: str, *, recursion_desired: bool) -> bytes:
    flags = FLAG_RD if recursion_desired else 0
    question = encode_name(name) + QUESTION_TAIL.pack(TYPE_A, CLASS_IN)
    return DNS_HEADER.pack(txid, flags, 1, 0, 0, 0) + question


def build_a_response(
    txid: int,
    question: Question,
    address: str,
    ttl: int,
    *,
    authoritative: bool,
    recursion_available: bool,
    recursion_desired: bool = False,
) -> bytes:
    ipaddress.IPv4Address(address)
    if not 1 <= ttl <= MAX_TTL:
        raise DnsError("invalid response TTL")
    flags = FLAG_QR
    if authoritative:
        flags |= FLAG_AA
    if recursion_available:
        flags |= FLAG_RA
    if recursion_desired:
        flags |= FLAG_RD
    wire_question = encode_name(question.name) + QUESTION_TAIL.pack(
        question.qtype, question.qclass
    )
    # The answer owner points backward to the question name at byte 12.
    answer = b"\xc0\x0c" + RR_HEADER.pack(TYPE_A, CLASS_IN, ttl, 4)
    answer += socket.inet_aton(address)
    return DNS_HEADER.pack(txid, flags, 1, 1, 0, 0) + wire_question + answer


def predict_next_txid(observed: int) -> int:
    return (observed * LCG_MULTIPLIER + LCG_INCREMENT) & 0xFFFF


def validate_loopback_endpoint(
    endpoint: tuple[str, int], *, purpose: str
) -> tuple[str, int]:
    try:
        address, port = endpoint
        parsed = ipaddress.ip_address(address)
    except (TypeError, ValueError) as exc:
        raise LabError(f"{purpose} is not a valid IPv4 endpoint") from exc
    if parsed.version != 4 or not parsed.is_loopback:
        raise LabError(f"{purpose} escaped IPv4 loopback")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise LabError(f"{purpose} has an invalid UDP port")
    return str(parsed), port


def make_udp_socket(address: str, port: int = 0) -> socket.socket:
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4 or not parsed.is_loopback:
        raise LabError("internal socket address escaped IPv4 loopback")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((address, port))
        sock.settimeout(0.10)
        return sock
    except BaseException:
        sock.close()
        raise


def validate_bound_loopback_udp_socket(
    sock: socket.socket, *, purpose: str
) -> tuple[str, int]:
    if sock.family != socket.AF_INET:
        raise LabError(f"{purpose} is not an IPv4 socket")
    if sock.type & socket.SOCK_DGRAM != socket.SOCK_DGRAM:
        raise LabError(f"{purpose} is not a UDP socket")
    try:
        endpoint = sock.getsockname()
    except OSError as exc:
        raise LabError(f"cannot inspect {purpose}: {exc}") from exc
    return validate_loopback_endpoint(endpoint, purpose=purpose)


class Authority:
    def __init__(
        self,
        sock: socket.socket,
        name: str,
        address: str,
        *,
        delay: float,
        observations: queue.Queue[QueryObservation] | None = None,
    ):
        self.socket = sock
        try:
            self.bound_endpoint = validate_bound_loopback_udp_socket(
                sock, purpose="authority socket"
            )
            self.name = canonical_name(name)
            self.address = str(ipaddress.IPv4Address(address))
            if delay < 0:
                raise LabError("authority delay cannot be negative")
            self.delay = delay
            self.observations = observations
            self.stop_event = threading.Event()
            self.response_sent = threading.Event()
            self.last_query: QueryObservation | None = None
            self.query_count = 0
            self.failure: Exception | None = None
            self.started = False
            self.thread = threading.Thread(
                target=self._run, name=f"authority-{self.name}", daemon=False
            )
        except BaseException:
            sock.close()
            raise

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.bound_endpoint

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def _run(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    packet, source = self.socket.recvfrom(MAX_PACKET + 1)
                except TimeoutError:
                    continue
                except OSError as exc:
                    if self.stop_event.is_set():
                        return
                    # Windows reports an ICMP port-unreachable from a blind UDP
                    # guess as WSAECONNRESET on a later recvfrom call.
                    if getattr(exc, "winerror", None) == 10054:
                        continue
                    raise
                try:
                    response_destination = validate_loopback_endpoint(
                        source, purpose="authority response destination"
                    )
                except LabError:
                    continue
                try:
                    txid, question, _rd = parse_query(packet)
                except DnsError:
                    continue
                if question.name != self.name:
                    continue

                observation = QueryObservation(
                    txid,
                    response_destination[0],
                    response_destination[1],
                    question.name,
                )
                self.last_query = observation
                self.query_count += 1
                if self.observations is not None:
                    self.observations.put(observation)
                if self.delay and self.stop_event.wait(self.delay):
                    return
                response = build_a_response(
                    txid,
                    question,
                    self.address,
                    60,
                    authoritative=True,
                    recursion_available=False,
                )
                self.socket.sendto(response, response_destination)
                self.response_sent.set()
        except Exception as exc:  # noqa: BLE001 - preserve a thread's failure
            self.failure = exc

    def send_forged_burst(self, txid: int, resolver_port: int) -> BurstEvidence:
        question = Question(TARGET_NAME, TYPE_A, CLASS_IN)
        packet = build_a_response(
            txid,
            question,
            POISONED_IP,
            60,
            authoritative=True,
            recursion_available=False,
        )
        destination = validate_loopback_endpoint(
            (LOOPBACK, resolver_port), purpose="forged-response destination"
        )
        sent = 0
        first_send_started_ns: int | None = None
        last_send_completed_ns = 0
        for wave in range(FORGED_BURST_WAVES):
            for _packet_number in range(FORGED_PACKETS_PER_WAVE):
                send_started_ns = time.monotonic_ns()
                if first_send_started_ns is None:
                    first_send_started_ns = send_started_ns
                if self.socket.sendto(packet, destination) != len(packet):
                    raise LabError("short UDP send while racing forged responses")
                last_send_completed_ns = time.monotonic_ns()
                sent += 1
            if wave + 1 < FORGED_BURST_WAVES:
                time.sleep(FORGED_WAVE_PAUSE)
        if first_send_started_ns is None:
            raise LabError("forged-response burst was empty")
        return BurstEvidence(sent, first_send_started_ns, last_send_completed_ns)

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        if self.started:
            self.thread.join(timeout=2.0)
            if self.thread.is_alive():
                raise LabError(f"authority thread did not stop: {self.name}")
        if self.failure is not None:
            raise LabError(f"authority {self.name} failed: {self.failure}")


class Resolver:
    def __init__(
        self,
        mode: str,
        probe_endpoint: tuple[str, int],
        target_endpoint: tuple[str, int],
    ):
        if mode not in MODE_POLICIES:
            raise ValueError(mode)
        self.mode = mode
        self.policy = MODE_POLICIES[mode]
        self.probe_endpoint = validate_loopback_endpoint(
            probe_endpoint, purpose="probe authority endpoint"
        )
        self.target_endpoint = validate_loopback_endpoint(
            target_endpoint, purpose="target authority endpoint"
        )
        client_socket: socket.socket | None = None
        shared_upstream: socket.socket | None = None
        try:
            client_socket = make_udp_socket(LOOPBACK)
            shared_upstream = (
                None if self.policy.random_port else make_udp_socket(LOOPBACK)
            )
            self.client_socket = client_socket
            self.shared_upstream = shared_upstream
            self.last_random_port: int | None = None
            self.lcg_state = secrets.randbits(16)
            self.cache: dict[str, tuple[str, float]] = {}
            self.trace: list[ResolutionTrace] = []
            self.cache_hits = 0
            self.rejected_datagrams = 0
            self.rejection_reasons: dict[str, int] = {}
            self.stop_event = threading.Event()
            self.failure: Exception | None = None
            self.started = False
            self.thread = threading.Thread(
                target=self._run, name=f"resolver-{mode}", daemon=False
            )
        except BaseException:
            if shared_upstream is not None:
                shared_upstream.close()
            if client_socket is not None:
                client_socket.close()
            raise

    @property
    def endpoint(self) -> tuple[str, int]:
        host, port = self.client_socket.getsockname()
        return str(host), int(port)

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def _next_txid(self) -> int:
        if self.policy.random_txid:
            return secrets.randbits(16)
        self.lcg_state = predict_next_txid(self.lcg_state)
        return self.lcg_state

    def _reject(self, reason: str) -> None:
        self.rejected_datagrams += 1
        self.rejection_reasons[reason] = self.rejection_reasons.get(reason, 0) + 1

    def _randomized_socket(self) -> socket.socket:
        for _attempt in range(256):
            candidate = 40000 + secrets.randbelow(20000)
            if candidate == self.last_random_port:
                continue
            try:
                sock = make_udp_socket(LOOPBACK, candidate)
            except OSError:
                continue
            self.last_random_port = candidate
            return sock
        raise LabError("could not reserve a randomized upstream UDP port")

    def _upstream_for(self, name: str) -> tuple[str, int]:
        if name == PROBE_NAME:
            return self.probe_endpoint
        if name == TARGET_NAME:
            return self.target_endpoint
        raise DnsError("name is outside the local lab zones")

    def _exchange(self, question: Question) -> ExchangeResult:
        destination = self._upstream_for(question.name)
        txid = self._next_txid()
        owned_socket = self.policy.random_port
        upstream = self._randomized_socket() if owned_socket else self.shared_upstream
        if upstream is None:
            raise LabError("resolver mode has no usable upstream socket")
        source_port = int(upstream.getsockname()[1])

        try:
            query = build_query(txid, question.name, recursion_desired=False)
            if upstream.sendto(query, destination) != len(query):
                raise LabError("short UDP send while forwarding resolver query")
            upstream_send_completed_ns = time.monotonic_ns()
            deadline = time.monotonic() + 1.0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DnsError("upstream response timed out")
                upstream.settimeout(min(0.10, remaining))
                try:
                    packet, source = upstream.recvfrom(MAX_PACKET + 1)
                except TimeoutError:
                    continue
                if len(packet) > MAX_PACKET:
                    self._reject("oversized")
                    continue

                # Weak modes check only the authority port. Strict modes bind a
                # response to the complete IPv4 endpoint.
                endpoint_ok = (
                    source == destination
                    if self.policy.strict_source
                    else source[1] == destination[1]
                )
                if not endpoint_ok:
                    self._reject("source_mismatch")
                    continue
                if len(packet) < DNS_HEADER.size:
                    self._reject("malformed_dns")
                    continue
                response_txid = DNS_HEADER.unpack_from(packet)[0]
                if response_txid != txid:
                    self._reject("txid_mismatch")
                    continue
                try:
                    address, ttl = parse_a_response(
                        packet, txid, question, require_authoritative=True
                    )
                except DnsError:
                    self._reject("invalid_dns")
                    continue
                return ExchangeResult(
                    address=address,
                    ttl=ttl,
                    txid=txid,
                    source_port=source_port,
                    accepted_source=source[0],
                    upstream_send_completed_ns=upstream_send_completed_ns,
                    response_accepted_ns=time.monotonic_ns(),
                )
        finally:
            if owned_socket:
                upstream.close()

    def _answer(self, packet: bytes, source: tuple[str, int]) -> None:
        txid, question, recursion_desired = parse_query(packet)
        now = time.monotonic()
        cached = self.cache.get(question.name)
        if cached is not None and cached[1] > now:
            address, expires = cached
            ttl = max(1, min(MAX_TTL, int(expires - now)))
            self.cache_hits += 1
            self.trace.append(
                ResolutionTrace(question.name, True, None, None, None, None, None)
            )
        else:
            exchange = self._exchange(question)
            address = exchange.address
            ttl = exchange.ttl
            self.cache[question.name] = (address, time.monotonic() + exchange.ttl)
            self.trace.append(
                ResolutionTrace(
                    question.name,
                    False,
                    exchange.txid,
                    exchange.source_port,
                    exchange.accepted_source,
                    exchange.upstream_send_completed_ns,
                    exchange.response_accepted_ns,
                )
            )
        response = build_a_response(
            txid,
            question,
            address,
            ttl,
            authoritative=False,
            recursion_available=True,
            recursion_desired=recursion_desired,
        )
        self.client_socket.sendto(response, source)

    def _run(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    packet, source = self.client_socket.recvfrom(MAX_PACKET + 1)
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        return
                    raise
                if source[0] != LOOPBACK or len(packet) > MAX_PACKET:
                    continue
                try:
                    self._answer(packet, source)
                except DnsError:
                    continue
        except Exception as exc:  # noqa: BLE001 - preserve a thread's failure
            self.failure = exc

    def close(self) -> None:
        self.stop_event.set()
        self.client_socket.close()
        if self.shared_upstream is not None:
            self.shared_upstream.close()
        if self.started:
            self.thread.join(timeout=2.0)
            if self.thread.is_alive():
                raise LabError(f"resolver thread did not stop: {self.mode}")
        if self.failure is not None:
            raise LabError(f"resolver {self.mode} failed: {self.failure}")


def client_query(
    endpoint: tuple[str, int],
    name: str,
    timeout: float = 1.5,
    *,
    send_observations: queue.Queue[int] | None = None,
) -> str:
    destination = validate_loopback_endpoint(
        endpoint, purpose="client resolver endpoint"
    )
    if timeout <= 0:
        raise LabError("client timeout must be positive")
    txid = secrets.randbits(16)
    question = Question(canonical_name(name), TYPE_A, CLASS_IN)
    packet = build_query(txid, question.name, recursion_desired=True)
    with make_udp_socket(LOOPBACK) as sock:
        deadline = time.monotonic() + timeout
        if sock.sendto(packet, destination) != len(packet):
            raise LabError("short UDP send while inducing client query")
        send_completed_ns = time.monotonic_ns()
        if send_observations is not None:
            try:
                send_observations.put_nowait(send_completed_ns)
            except queue.Full as exc:
                raise LabError("client send-observation queue is full") from exc
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("client DNS query timed out")
            sock.settimeout(min(0.10, remaining))
            try:
                response, source = sock.recvfrom(MAX_PACKET + 1)
            except TimeoutError:
                continue
            if source != destination or len(response) > MAX_PACKET:
                continue
            try:
                address, _ttl = parse_a_response(
                    response, txid, question, require_authoritative=False
                )
            except DnsError:
                continue
            return address


def reserve_authorities() -> tuple[socket.socket, socket.socket]:
    for _attempt in range(128):
        victim = make_udp_socket(AUTHORITY_IP)
        port = int(victim.getsockname()[1])
        try:
            attacker = make_udp_socket(ATTACKER_IP, port)
        except OSError:
            victim.close()
            continue
        except BaseException:
            victim.close()
            raise
        return victim, attacker
    raise LabError("could not reserve matching loopback authority ports")


def _run_scenario_attempt(mode: str) -> ScenarioResult:
    if mode not in MODE_POLICIES:
        raise ValueError(mode)
    policy = MODE_POLICIES[mode]
    victim_socket: socket.socket | None = None
    attacker_socket: socket.socket | None = None
    observations: queue.Queue[QueryObservation] = queue.Queue()
    services: list[Authority | Resolver] = []
    workers: list[threading.Thread] = []
    try:
        victim_socket, attacker_socket = reserve_authorities()
        victim = Authority(
            victim_socket,
            TARGET_NAME,
            LEGITIMATE_IP,
            delay=0.25,
        )
        services.append(victim)
        victim_socket = None
        attacker = Authority(
            attacker_socket,
            PROBE_NAME,
            PROBE_IP,
            delay=0.0,
            observations=observations,
        )
        services.append(attacker)
        attacker_socket = None
        resolver = Resolver(mode, attacker.endpoint, victim.endpoint)
        services.append(resolver)

        # Construction and every partial start are now covered by the cleanup
        # below. Unstarted services still own sockets and are safe to close.
        for service in services:
            service.start()

        probe_answer = client_query(resolver.endpoint, PROBE_NAME)
        if probe_answer != PROBE_IP:
            raise LabError(f"probe returned {probe_answer}, expected {PROBE_IP}")
        try:
            observed = observations.get(timeout=1.0)
        except queue.Empty as exc:
            raise LabError("attacker did not observe the probe transaction") from exc
        predicted = predict_next_txid(observed.txid)

        holder: dict[str, object] = {}
        induction_observations: queue.Queue[int] = queue.Queue(maxsize=1)

        def query_target() -> None:
            try:
                holder["answer"] = client_query(
                    resolver.endpoint,
                    TARGET_NAME,
                    send_observations=induction_observations,
                )
            except Exception as exc:  # noqa: BLE001 - return failure to owner
                holder["error"] = exc

        client_thread = threading.Thread(target=query_target, name="target-client")
        workers.append(client_thread)

        # This timestamp comes from the attacker's own inducing client. The
        # fixed delay is chosen before the run; no resolver or victim event
        # controls when the forged burst begins.
        client_thread.start()
        try:
            induction_send_completed_ns = induction_observations.get(timeout=1.0)
        except queue.Empty as exc:
            raise LabError("inducing client did not report its send time") from exc
        attack_not_before_ns = induction_send_completed_ns + int(
            ATTACK_AFTER_INDUCTION_SECONDS * 1_000_000_000
        )
        while True:
            remaining_ns = attack_not_before_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                break
            time.sleep(remaining_ns / 1_000_000_000)
        burst = attacker.send_forged_burst(predicted, observed.source_port)

        client_thread.join(timeout=2.0)
        if client_thread.is_alive():
            raise LabError("target client did not finish")
        if "error" in holder:
            raise LabError(f"target query failed: {holder['error']}")
        expected_burst = FORGED_BURST_WAVES * FORGED_PACKETS_PER_WAVE
        if burst.packets_sent != expected_burst:
            raise LabError(
                f"forged burst sent {burst.packets_sent}, expected {expected_burst}"
            )
        first_answer = str(holder.get("answer"))

        if not victim.response_sent.wait(timeout=1.0):
            raise LabError("delayed legitimate authority did not answer")
        second_answer = client_query(resolver.endpoint, TARGET_NAME)

        target_observation = victim.last_query
        if target_observation is None:
            raise LabError("missing target authority observation")
        target_traces = [trace for trace in resolver.trace if trace.name == TARGET_NAME]
        if (
            len(target_traces) != 2
            or target_traces[0].cache_hit
            or not target_traces[1].cache_hit
        ):
            raise LabError("resolver trace does not show miss followed by cache hit")
        accepted_source = target_traces[0].accepted_source
        if accepted_source is None:
            raise LabError("uncached target trace lacks an accepted source")
        target_upstream_send_completed_ns = target_traces[0].upstream_send_completed_ns
        accepted_response_ns = target_traces[0].response_accepted_ns
        if target_upstream_send_completed_ns is None or accepted_response_ns is None:
            raise LabError("uncached target trace lacks monotonic timing evidence")
        if victim.query_count != 1:
            raise LabError("cached query unexpectedly reached the authority")

        if burst.first_send_started_ns <= target_upstream_send_completed_ns:
            raise ScenarioInconclusive("forge_preceded_target_upstream_send")
        forge_after_upstream_us = (
            burst.first_send_started_ns - target_upstream_send_completed_ns
        ) // 1_000

        prediction_matched = target_observation.txid == predicted
        port_reused = target_observation.source_port == observed.source_port
        if mode == "random_txid" and prediction_matched:
            raise ScenarioInconclusive("random_txid_collision")
        if not policy.random_txid and not prediction_matched:
            raise LabError("LCG prediction did not match the target transaction")
        if policy.random_port and port_reused:
            raise LabError("randomized target query reused the observed probe port")
        if not policy.random_port and not port_reused:
            raise LabError("fixed-port resolver changed its upstream source port")

        if mode == "vulnerable":
            if first_answer != POISONED_IP or second_answer != POISONED_IP:
                raise LabError("predictable resolver resisted the forged response")
            if accepted_source != ATTACKER_IP:
                raise LabError("poison was not sourced by the attacker authority")
            if accepted_response_ns < burst.first_send_started_ns:
                raise LabError("forged answer was accepted before the burst began")
            forged_outcome = "accepted"
        else:
            if first_answer != LEGITIMATE_IP or second_answer != LEGITIMATE_IP:
                raise LabError(f"{mode} control accepted the predictor's forgery")
            if accepted_source != AUTHORITY_IP:
                raise LabError(f"{mode} control did not accept the real authority")

            if policy.random_port:
                forged_outcome = "missed_randomized_port"
            elif policy.random_txid:
                if resolver.rejection_reasons.get("txid_mismatch", 0) < 1:
                    raise LabError(
                        "random-TXID control did not record forged rejection"
                    )
                forged_outcome = "rejected_txid"
            elif policy.strict_source:
                if resolver.rejection_reasons.get("source_mismatch", 0) < 1:
                    raise LabError(
                        "strict-source control did not record forged rejection"
                    )
                forged_outcome = "rejected_source"
            else:
                raise LabError(f"unclassified control outcome for {mode}")

        return ScenarioResult(
            mode=mode,
            policy=policy,
            attempts=1,
            inconclusive_retries=0,
            retry_reasons=[],
            observed_txid=observed.txid,
            predicted_txid=predicted,
            observed_upstream_port=observed.source_port,
            target_txid=target_observation.txid,
            target_upstream_port=target_observation.source_port,
            prediction_matched=prediction_matched,
            port_reused=port_reused,
            induction_send_completed_ns=induction_send_completed_ns,
            target_upstream_send_completed_ns=target_upstream_send_completed_ns,
            first_forged_send_started_ns=burst.first_send_started_ns,
            last_forged_send_completed_ns=burst.last_send_completed_ns,
            accepted_response_ns=accepted_response_ns,
            forge_after_upstream_us=forge_after_upstream_us,
            timing_order_verified=True,
            forged_packets_sent=burst.packets_sent,
            forged_outcome=forged_outcome,
            accepted_source=accepted_source,
            first_answer=first_answer,
            second_answer=second_answer,
            authority_queries=victim.query_count,
            cache_hits=resolver.cache_hits,
            rejected_datagrams=resolver.rejected_datagrams,
            rejection_reasons=dict(sorted(resolver.rejection_reasons.items())),
        )
    finally:
        active_error = sys.exc_info()[1]
        failures: list[str] = []
        for worker in workers:
            if worker.is_alive():
                worker.join(timeout=2.0)
        for service in reversed(services):
            try:
                service.close()
            except Exception as exc:  # noqa: BLE001 - finish remaining cleanup
                failures.append(str(exc))
        # Non-None sockets never completed ownership transfer to an Authority.
        if victim_socket is not None:
            victim_socket.close()
        if attacker_socket is not None:
            attacker_socket.close()
        for worker in workers:
            if worker.is_alive():
                worker.join(timeout=0.5)
            if worker.is_alive():
                failures.append(f"worker thread did not stop: {worker.name}")
        if failures:
            cleanup_error = LabError("cleanup failed: " + "; ".join(failures))
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error


def run_scenario(mode: str) -> ScenarioResult:
    retry_reasons: list[str] = []
    for attempt in range(1, MAX_SCENARIO_ATTEMPTS + 1):
        try:
            result = _run_scenario_attempt(mode)
        except ScenarioInconclusive as exc:
            retry_reasons.append(str(exc))
            continue
        return replace(
            result,
            attempts=attempt,
            inconclusive_retries=attempt - 1,
            retry_reasons=retry_reasons,
        )
    reasons = ", ".join(retry_reasons)
    raise LabError(
        f"{mode} remained inconclusive after {MAX_SCENARIO_ATTEMPTS} attempts: "
        f"{reasons}"
    )


def run_lab(runs: int) -> dict[str, object]:
    if not 1 <= runs <= 50:
        raise LabError("runs must be between 1 and 50")
    records: list[dict[str, object]] = []
    for run_number in range(1, runs + 1):
        matrix = {mode: run_scenario(mode) for mode in MODE_ORDER}
        record: dict[str, object] = {"run": run_number}
        record.update({mode: asdict(result) for mode, result in matrix.items()})
        records.append(record)
        outcomes = " ".join(
            f"{mode}={matrix[mode].forged_outcome}"
            f"(retries={matrix[mode].inconclusive_retries})"
            for mode in MODE_ORDER
        )
        print(
            f"[{run_number:02d}/{runs:02d}] {outcomes}",
            file=sys.stderr,
            flush=True,
        )
    retry_counts = {
        mode: sum(
            int(record[mode]["inconclusive_retries"])
            for record in records
            if isinstance(record[mode], dict)
        )
        for mode in MODE_ORDER
    }
    return {
        "runs": runs,
        "modes": list(MODE_ORDER),
        "scenarios": runs * len(MODE_ORDER),
        "max_attempts_per_scenario": MAX_SCENARIO_ATTEMPTS,
        "inconclusive_retries": retry_counts,
        "total_inconclusive_retries": sum(retry_counts.values()),
        "vulnerable_poisoned": runs,
        "controls_resisted": {
            mode: runs for mode in MODE_ORDER if mode != "vulnerable"
        },
        "fixed_resisted": runs,
        "records": records,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="run the contained false-answer DNS poisoning lab",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--run-local-lab",
        action="store_true",
        required=True,
        help="acknowledge and run the IPv4-loopback-only lab",
    )
    parser.add_argument(
        "--runs", type=int, default=5, help="repeat the five-mode matrix (1..50)"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = run_lab(args.runs)
    except (LabError, DnsError, OSError) as exc:
        print(f"falseanswer: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
