# ghostframe / oraclestrike / falseanswer

Three independent Python programs. They share no framework, target list, or
remote mode. Each one performs its mechanism for real inside a contained local
lab and refuses to start without `--run-local-lab`. Run the commands below from
this directory.

## ghostframe

A Linux x86-64 `ptrace` execution primitive. It creates a sacrificial child,
overwrites code beginning at the child's stopped RIP with a position-independent
`write(2)` payload, proves execution with a PID-and-nonce marker, restores code
and general-purpose register state, detaches, and proves the restored program
resumed by watching its heartbeat advance.

```sh
python3 ghostframe/ghostframe.py --run-local-lab --repeat 25
```

See [`ghostframe/README.md`](ghostframe/README.md). Native x86-64 Linux or WSL
is required.

## oraclestrike

A complete adaptive RSA PKCS#1 v1.5 padding-oracle break in pure Python. It
generates a fresh local key and ciphertext, exposes only a strict Boolean
oracle to the attack, searches conforming multipliers, narrows the exact
plaintext interval, and verifies recovery of the randomized encoded block.

```powershell
python .\oraclestrike\oraclestrike.py --run-local-lab
```

See [`oraclestrike/README.md`](oraclestrike/README.md). Expect a real adaptive
attack: query counts and runtime vary between fresh keys.

## falseanswer

A wire-level UDP DNS cache-poisoning race on IPv4 loopback. It learns a
resolver's LCG state and fixed source port through an attacker-controlled probe,
predicts the next transaction ID, sends a blind forged-answer burst, and proves
the poisoned value was cached. Four control modes independently isolate random
TXIDs, random ports, and strict response-source validation.

```powershell
python .\falseanswer\falseanswer.py --run-local-lab --runs 10
```

See [`falseanswer/README.md`](falseanswer/README.md). All sockets are fenced to
`127.0.0.0/8`; the IPs carried in answer data are RFC documentation addresses.

## Verified here

- `ghostframe`: 25/25 fresh children injected, trapped, restored, detached,
  resumed, and reaped; every injection mapping was executable and non-writable.
- `oraclestrike`: exact block and message recovery on a fresh final-source run
  in 256,516 oracle queries and 8.71 seconds; the 10,000-query hard-stop and
  missing-gate controls also fired at their stated boundaries.
- `falseanswer`: 10/10 complete matrices, or 50/50 scenarios. Every vulnerable
  resolver cached the forged answer, and every independently hardened mode
  resisted it for the expected reason while accepting the legitimate answer.

Python source is standard-library-only. The individual READMEs define the
mechanism, evidence, containment boundary, and platform requirements precisely.
