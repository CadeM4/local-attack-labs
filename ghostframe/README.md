# ghostframe

`ghostframe.py` is a constrained Linux x86-64 `ptrace` injection exercise. It
forks one sacrificial child, proves the parent/child relationship, attaches to
that PID, replaces code at the stopped RIP, and runs a position-independent
`write(2)` payload. Before injection, the tracer closes its copy of the pipe's
write end and verifies that its reader and the child's inherited descriptor
resolve to the same pipe inode. Under that construction the child retains the
only created writer. The payload writes a PID-and-nonce marker and stops on
`INT3`.

The tracer validates the trap RIP and syscall return value, captures the exact
marker under a fixed limit, restores the original executable bytes and Linux
x86-64 `user_regs_struct` state with read-back checks, and detaches. The restored
spin stub then has to advance a counter in a separate shared mapping before the
tracer will terminate and reap the child. A matching hash is therefore not the
final proof: the original code must execute again after detach.

The child code page is created RW, populated with an `ENDBR64` indirect-entry
landing pad and the spin stub, and changed directly to RX before `fork`; it is
never RWX. After attach, the tracer parses `/proc/<pid>/maps` and requires the
entire injection to reside in a readable, executable, non-writable mapping.
`PTRACE_POKETEXT` is the mechanism that modifies it. The heartbeat lives in a
different `MAP_SHARED` RW page and is never executable.

The runnable path has no PID argument and never selects an existing process.
Low-level ptrace and memory helpers require a pidfd-backed handle that validates
a direct-child identity; they do not accept a raw PID. Terminal waits and
`ECHILD` retire that handle before later cleanup can signal it. The child sets
`PR_SET_PDEATHSIG` so an unexpected tracer death does not leave the spin stub
behind. Both the CLI and direct `run_once` entry point refuse to run without an
explicit local-lab acknowledgement.

Run it from this directory under native x86-64 Linux or Ubuntu on WSL:

```sh
python3 ghostframe.py --run-local-lab
python3 ghostframe.py --run-local-lab --repeat 25
```

Each run emits the child PID, pipe inode, nonce-bearing proof, injection and trap
addresses, hashes of the saved/restored code, a register-snapshot hash, and the
mapping permissions, pre/post-detach heartbeat values, and cleanup result. If an
error path cannot prove that modified code and registers were restored, it does
not detach the corrupted tracee; it kills and reaps it while tracing remains in
force. `ptrace` policy still applies. Normal Ubuntu/WSL parent-to-child tracing
works with the usual Yama policy; a host configured to prohibit all attachments
will reject the attach rather than falling back to another target.

Dependencies: Python 3 with `os.pidfd_open`/`signal.pidfd_send_signal`, a Linux
kernel with pidfd support, and glibc. The implementation otherwise uses only the
standard library and `ctypes` bindings to the host C library.

## Verification

On 2026-08-28, Ubuntu under WSL completed a 25-child run with 25 distinct PIDs,
nonces, and pipe inodes. Every injection mapping was `r-xp`. All 25 runs used a
73-byte injected image, reached the expected `INT3`, returned the full marker
write, restored matching code hashes and `user_regs_struct` snapshots, detached,
then observed the restored heartbeat advance before reaping the child after
`SIGTERM`. In the final-source run, post-detach heartbeat deltas ranged from
1,254 to 88,298 and per-child elapsed time was 15-17 ms, with two
instruction-boundary RIPs observed. The missing-gate control exited with status
2 before creating a child.
