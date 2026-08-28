# oraclestrike

`oraclestrike.py` is a stand-alone local reproduction of the adaptive RSA
PKCS#1 v1.5 chosen-ciphertext attack. It generates a fresh RSA keypair and a
strict padding oracle in-process, encrypts a caller-selected message, then
recovers the complete encoded block without giving the attack routine the
private key.

The vulnerable side returns one bit: whether RSA decryption produced exactly
`00 02 || PS || 00 || M`, with at least eight nonzero bytes in `PS`. The attack
uses RSA's multiplicative property, searches for conforming multipliers, and
narrows the possible plaintext intervals after every positive response. The
oracle's RSA private operation uses CRT so a realistic strict-oracle query
count remains practical in pure Python.

There is no socket code, URL parsing, target argument, key loading, or remote
mode. The required switch is intentional:

```powershell
python .\oraclestrike.py --run-local-lab
```

Useful bounded lab controls:

```powershell
python .\oraclestrike.py --run-local-lab `
  --bits 256 `
  --exponent 3 `
  --message "local oracle proof" `
  --query-budget 5000000 `
  --time-budget 180 `
  --json
```

- `--bits` accepts byte-aligned sizes from 256 through 512. These intentionally
  small research keys keep the demonstration finite; they are not suitable for
  real cryptographic use.
- `--exponent` accepts `3` or `65537`. The default `3` cuts public-side modular
  exponentiation overhead in the hot search loop; it does not expose the
  plaintext by itself or bypass any oracle step. Use `65537` to model the common
  modern exponent at a lower query rate.
- `--query-budget` is clamped to 10,000..20,000,000 and applies exactly to
  adaptive attack queries; the five post-recovery controls are counted
  separately.
- `--time-budget` is clamped to 5..300 seconds and checked before every oracle
  call (a callback already in progress is not preempted).
- `--quiet` suppresses progress lines, and `--json` makes the final evidence
  machine-readable.

The final report includes key-generation and attack time, queries by attack
phase, accepting-response count, query rate, ciphertext and recovered-block
digests, and exact block/plaintext equality. It also encrypts several malformed
blocks and confirms that the same live oracle rejects wrong block types, short
padding strings, early zero bytes, missing separators, and the zero ciphertext.

Query count varies with every key and randomized padding string. The 256-bit
default is the useful smoke-test size. Larger settings make the interval math
more interesting but a strict oracle can consume millions of private-key
operations; the budget failures are deliberate and explicit rather than an
unbounded loop.

## Verification

Fresh 256-bit runs under Python 3.13 recovered the exact randomized encoded
block and UTF-8 message, not just a suffix inferred from the fixture. One
default `e=3` run took 255,672 queries and 10.31 seconds; the final-source
verification run took 256,516 queries and 8.71 seconds. Two `e=65537` runs took
951,213 queries / 38.07 seconds and 1,666,379 queries / 83.56 seconds. Every run
rejected all five negative controls. These are observations rather than golden
query counts; key generation and PKCS padding use `secrets`, so the search
trajectory intentionally changes each time.
