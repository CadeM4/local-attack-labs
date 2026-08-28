# falseanswer

`falseanswer.py` is an IPv4-loopback DNS cache-poisoning lab. It runs a delayed
authority for `archive.service.test`, an attacker authority for
`state.attacker.test`, a caching resolver, and UDP clients. Every exchange uses
real DNS wire messages and strict parsing for the lab's IN/A profile.

The attacker first induces a query to its own authority, observes the resolver's
source port and 16-bit TXID, and applies the known LCG predictor. It then induces
the target query. The inducing client reports only completion of its own UDP
send, an attacker-visible action. After a fixed 50 ms delay chosen before the
run, the attacker sends a bounded 64-datagram burst; it never waits for or reads
victim-authority state.

Resolver timestamps are evidence, not a timing oracle. After the exchange, the
lab requires the resolver's target-upstream `sendto` to have completed before
the first forged `sendto` began. JSON records both monotonic timestamps, the
accepted-response timestamp, and their positive `forge_after_upstream_us`
delta. Thus a reported vulnerable success cannot come from a pre-queued answer.

The five-mode matrix isolates each defense:

| Mode | TXID | Upstream port | Source check | Expected forgery outcome |
| --- | --- | --- | --- | --- |
| `vulnerable` | LCG | fixed | port only | accepted and cached |
| `random_txid` | random | fixed | port only | reaches socket; TXID rejected |
| `random_port` | LCG | per-query | port only | misses target socket |
| `strict_source` | LCG | fixed | full endpoint | reaches socket; source rejected |
| `fixed` | random | per-query | full endpoint | misses target socket |

Every control must accept and cache legitimate `192.0.2.44`; vulnerable mode
must return and cache forged `203.0.113.66`. A second lookup proves the cache hit
without another authority query. A random-TXID control can match one 16-bit
guess with probability 1/65,536. That result is explicitly inconclusive, not a
defense failure: the scenario retries from clean state up to five total attempts
and reports `attempts`, `inconclusive_retries`, and `retry_reasons`. A TXID
collision is harmless in `fixed` because the forged packet misses its randomized
port. Timing-order inconclusives use the same bounded retry path.

## Run

Python 3.10 or newer is sufficient; there are no third-party dependencies.

```sh
python3 falseanswer.py --run-local-lab
python3 falseanswer.py --run-local-lab --runs 10
```

Progress is written to stderr. Stdout contains exactly one compact JSON
document. The gate is mandatory, option abbreviations are disabled, and there
are no host or upstream options.

Participants bind only `127.0.0.1`, `127.0.0.2`, and `127.0.0.3`. Resolver and
client destinations are checked at use. Each authority also validates that its
owned socket is bound UDP/IPv4 loopback and refuses to respond to a non-loopback
source, including when these classes are imported. Documentation A-record
addresses are payload data only and are never contacted. Socket acquisition,
partial construction, service startup, threads, and cleanup are all covered by
failure handling.

This demonstrates poisoning caused by predictable TXIDs, fixed source-port
reuse, and incomplete source validation. It does not spoof raw source IP. The
attacker uses a different loopback IP on the same UDP port as the victim
authority.
