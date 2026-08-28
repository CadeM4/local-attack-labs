#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import mmap
import os
import platform
import secrets
import selectors
import signal
import struct
import sys
import time
from dataclasses import asdict, dataclass


PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

PR_SET_PDEATHSIG = 1
SYS_WRITE = 1

WORD = ctypes.sizeof(ctypes.c_long)
WORD_MASK = (1 << (WORD * 8)) - 1
MAX_MARKER = 192
MAX_CAPTURE = 512
MAX_REPEAT = 64


class LabError(RuntimeError):
    pass


class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


@dataclass(frozen=True)
class RunResult:
    child_pid: int
    nonce: str
    marker: str
    pipe: str
    injection_rip: str
    trap_rip: str
    mapping_permissions: str
    payload_bytes: int
    original_code_sha256: str
    restored_code_sha256: str
    register_snapshot_sha256: str
    code_restored: bool
    registers_restored: bool
    detached: bool
    heartbeat_before: int
    heartbeat_after: int
    heartbeat_delta: int
    termination_signal: str
    elapsed_ms: int


_LIBC: ctypes.CDLL | None = None
_CHILD_HANDLE_KEY = object()


def _proc_identity(pid: int) -> tuple[int, int]:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stat_file:
            record = stat_file.read()
    except OSError as exc:
        raise LabError(f"cannot read process identity for pid {pid}: {exc}") from exc
    closing_paren = record.rfind(")")
    if closing_paren < 0:
        raise LabError(f"malformed /proc/{pid}/stat record")
    fields = record[closing_paren + 2 :].split()
    if len(fields) <= 19:
        raise LabError(f"short /proc/{pid}/stat record")
    try:
        return int(fields[1]), int(fields[19])
    except ValueError as exc:
        raise LabError(f"invalid /proc/{pid}/stat identity fields") from exc


class _OwnedChild:
    __slots__ = ("_pid", "_pidfd", "_start_time", "reaped", "terminal_status")

    def __init__(self, pid: int, key: object):
        if key is not _CHILD_HANDLE_KEY:
            raise TypeError("owned child handles cannot be constructed externally")
        parent_pid, start_time = _proc_identity(pid)
        if parent_pid != os.getpid():
            raise LabError(f"pid {pid} is not a direct child of this tracer")
        try:
            pidfd = os.pidfd_open(pid, 0)
        except OSError as exc:
            raise LabError(f"pidfd_open({pid}) failed: {exc}") from exc
        self._pid = pid
        self._pidfd = pidfd
        self._start_time = start_time
        self.reaped = False
        self.terminal_status: int | None = None

    @property
    def pid(self) -> int:
        return self._pid

    def require_live(self) -> None:
        if self.reaped:
            raise LabError(f"child {self._pid} has already been reaped")
        try:
            signal.pidfd_send_signal(self._pidfd, 0, None, 0)
        except ProcessLookupError as exc:
            raise LabError(f"owned child {self._pid} is no longer live") from exc
        parent_pid, start_time = _proc_identity(self._pid)
        if parent_pid != os.getpid() or start_time != self._start_time:
            raise LabError(f"owned child identity changed for pid {self._pid}")

    def send_signal(self, signum: int, *, missing_ok: bool = False) -> bool:
        if self.reaped:
            if missing_ok:
                return False
            raise LabError(f"refusing to signal reaped child {self._pid}")
        try:
            signal.pidfd_send_signal(self._pidfd, signum, None, 0)
            return True
        except ProcessLookupError:
            if missing_ok:
                return False
            raise LabError(f"owned child {self._pid} exited before signal delivery")

    def wait(self, timeout: float, *, stopped: bool) -> int:
        if self.reaped:
            raise LabError(f"child {self._pid} has already been reaped")
        deadline = time.monotonic() + timeout
        flags = os.WNOHANG | (os.WUNTRACED if stopped else 0)
        while True:
            try:
                waited_pid, status = os.waitpid(self._pid, flags)
            except InterruptedError:
                continue
            except ChildProcessError as exc:
                self.reaped = True
                raise LabError(f"lost child ownership for pid {self._pid}") from exc
            if waited_pid == self._pid:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self.reaped = True
                    self.terminal_status = status
                return status
            if time.monotonic() >= deadline:
                state = "trace stop" if stopped else "termination"
                raise LabError(f"timed out waiting for pid {self._pid} {state}")
            time.sleep(0.005)

    def close(self) -> None:
        if self._pidfd >= 0:
            os.close(self._pidfd)
            self._pidfd = -1


def _libc() -> ctypes.CDLL:
    global _LIBC
    if _LIBC is None:
        library = ctypes.CDLL(None, use_errno=True)
        library.ptrace.restype = ctypes.c_long
        library.ptrace.argtypes = (
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        library.mprotect.restype = ctypes.c_int
        library.mprotect.argtypes = (
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        )
        library.prctl.restype = ctypes.c_int
        library.prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        _LIBC = library
    return _LIBC


def require_linux_x86_64() -> None:
    machine = platform.machine().lower()
    failures: list[str] = []
    if sys.platform != "linux":
        failures.append(f"platform is {sys.platform!r}, not Linux")
    if machine not in {"x86_64", "amd64"}:
        failures.append(f"machine is {machine!r}, not x86-64")
    if sys.byteorder != "little":
        failures.append("host is not little-endian")
    if ctypes.sizeof(ctypes.c_void_p) != 8 or WORD != 8:
        failures.append("process ABI is not LP64")
    if not hasattr(os, "fork") or not os.path.isdir("/proc/self"):
        failures.append("fork or procfs is unavailable")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        failures.append("Python or the kernel lacks pidfd process identity support")
    if failures:
        raise LabError("unsupported host: " + "; ".join(failures))


def _pointer(value: int) -> ctypes.c_void_p:
    return ctypes.c_void_p(value & WORD_MASK)


def _ptrace(
    request: int,
    child: _OwnedChild,
    address: int = 0,
    data: int = 0,
) -> int:
    child.require_live()
    pid = child.pid
    ctypes.set_errno(0)
    result = _libc().ptrace(request, pid, _pointer(address), _pointer(data))
    saved_errno = ctypes.get_errno()
    if result == -1 and saved_errno:
        name = errno.errorcode.get(saved_errno, str(saved_errno))
        raise LabError(
            f"ptrace request {request} for pid {pid} failed: "
            f"{name}: {os.strerror(saved_errno)}"
        )
    return result


def _ptrace_regs(
    request: int,
    child: _OwnedChild,
    registers: UserRegsStruct,
) -> None:
    child.require_live()
    pid = child.pid
    ctypes.set_errno(0)
    result = _libc().ptrace(
        request,
        pid,
        ctypes.c_void_p(),
        ctypes.cast(ctypes.byref(registers), ctypes.c_void_p),
    )
    saved_errno = ctypes.get_errno()
    if result == -1:
        name = errno.errorcode.get(saved_errno, str(saved_errno))
        raise LabError(
            f"ptrace register request {request} for pid {pid} failed: "
            f"{name}: {os.strerror(saved_errno)}"
        )


def _get_registers(child: _OwnedChild) -> UserRegsStruct:
    registers = UserRegsStruct()
    _ptrace_regs(PTRACE_GETREGS, child, registers)
    return registers


def _set_registers(child: _OwnedChild, registers: UserRegsStruct) -> None:
    _ptrace_regs(PTRACE_SETREGS, child, registers)


def _peek_word(child: _OwnedChild, address: int) -> int:
    if address % WORD:
        raise LabError(f"unaligned PEEKTEXT address: 0x{address:x}")
    return _ptrace(PTRACE_PEEKTEXT, child, address) & WORD_MASK


def _poke_word(child: _OwnedChild, address: int, value: int) -> None:
    if address % WORD:
        raise LabError(f"unaligned POKETEXT address: 0x{address:x}")
    _ptrace(PTRACE_POKETEXT, child, address, value & WORD_MASK)


def _read_code(child: _OwnedChild, address: int, length: int) -> bytes:
    if length < 0:
        raise ValueError("negative read length")
    if not length:
        return b""
    aligned_start = address & ~(WORD - 1)
    aligned_end = (address + length + WORD - 1) & ~(WORD - 1)
    image = bytearray()
    for cursor in range(aligned_start, aligned_end, WORD):
        image.extend(struct.pack("<Q", _peek_word(child, cursor)))
    offset = address - aligned_start
    return bytes(image[offset : offset + length])


def _write_code(child: _OwnedChild, address: int, replacement: bytes) -> None:
    if not replacement:
        return
    aligned_start = address & ~(WORD - 1)
    aligned_end = (address + len(replacement) + WORD - 1) & ~(WORD - 1)
    image = bytearray(
        _read_code(child, aligned_start, aligned_end - aligned_start)
    )
    offset = address - aligned_start
    image[offset : offset + len(replacement)] = replacement
    for cursor in range(0, len(image), WORD):
        value = struct.unpack_from("<Q", image, cursor)[0]
        _poke_word(child, aligned_start + cursor, value)


def describe_wait_status(status: int) -> str:
    if os.WIFEXITED(status):
        return f"exit({os.WEXITSTATUS(status)})"
    if os.WIFSIGNALED(status):
        return f"signal({signal.Signals(os.WTERMSIG(status)).name})"
    if os.WIFSTOPPED(status):
        return f"stop({signal.Signals(os.WSTOPSIG(status)).name})"
    if hasattr(os, "WIFCONTINUED") and os.WIFCONTINUED(status):
        return "continued"
    return f"wait-status(0x{status:x})"


def _require_stop(child: _OwnedChild, status: int, expected_signal: int) -> None:
    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != expected_signal:
        raise LabError(
            f"pid {child.pid} produced {describe_wait_status(status)}; expected "
            f"stop({signal.Signals(expected_signal).name})"
        )


def read_exact_bounded(
    fd: int,
    length: int,
    timeout: float,
    *,
    label: str,
    limit: int,
) -> bytes:
    if length < 0 or length > limit:
        raise LabError(f"{label} length {length} exceeds limit {limit}")
    selector = selectors.DefaultSelector()
    output = bytearray()
    os.set_blocking(fd, False)
    selector.register(fd, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while len(output) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise LabError(f"timed out waiting for {label}")
            try:
                chunk = os.read(fd, min(4096, length - len(output)))
            except BlockingIOError:
                continue
            except InterruptedError:
                continue
            if not chunk:
                raise LabError(f"EOF while reading {label}: {len(output)}/{length} bytes")
            output.extend(chunk)
        return bytes(output)
    finally:
        selector.close()


def build_injected_writer(fd: int, marker: bytes) -> tuple[bytes, int]:
    if fd < 0 or fd > 0x7FFFFFFF:
        raise LabError(f"pipe descriptor is outside the shellcode ABI: {fd}")
    if not marker or len(marker) > MAX_MARKER:
        raise LabError(f"marker length must be between 1 and {MAX_MARKER}")

    code = bytearray()
    code += b"\xb8" + struct.pack("<I", SYS_WRITE)       # mov eax, SYS_write
    code += b"\xbf" + struct.pack("<I", fd)              # mov edi, fd
    lea_at = len(code)
    code += b"\x48\x8d\x35\x00\x00\x00\x00"          # lea rsi, [rip+marker]
    code += b"\xba" + struct.pack("<I", len(marker))     # mov edx, marker length
    code += b"\x0f\x05"                                  # syscall
    int3_at = len(code)
    code += b"\xcc"                                       # hand control back to tracer
    marker_at = len(code)
    displacement = marker_at - (lea_at + 7)
    struct.pack_into("<i", code, lea_at + 3, displacement)
    code += marker
    return bytes(code), int3_at


def build_heartbeat_page() -> tuple[mmap.mmap, int]:
    page = mmap.mmap(
        -1,
        mmap.PAGESIZE,
        flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
        prot=mmap.PROT_READ | mmap.PROT_WRITE,
    )
    page[0:8] = b"\x00" * 8
    exported = ctypes.c_char.from_buffer(page)
    address = ctypes.addressof(exported)
    del exported
    if address % 8:
        page.close()
        raise LabError(f"heartbeat counter is not naturally aligned: 0x{address:x}")
    return page, address


def heartbeat_value(page: mmap.mmap) -> int:
    return struct.unpack("<Q", page[0:8])[0]


def stable_heartbeat(page: mmap.mmap, timeout: float = 0.05) -> int:
    deadline = time.monotonic() + timeout
    previous = heartbeat_value(page)
    while time.monotonic() < deadline:
        time.sleep(0.002)
        current = heartbeat_value(page)
        if current == previous:
            return current
        previous = current
    raise LabError("heartbeat did not become stable while the child was stopped")


def wait_for_heartbeat(page: mmap.mmap, previous: int, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = heartbeat_value(page)
        if current != previous:
            return current
        time.sleep(0.001)
    raise LabError("restored child did not advance its heartbeat after detach")


def build_spin_page(
    sync_write_fd: int,
    heartbeat_address: int,
) -> tuple[mmap.mmap, int, int, int, int]:
    page_size = mmap.PAGESIZE
    page = mmap.mmap(
        -1,
        page_size,
        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        prot=mmap.PROT_READ | mmap.PROT_WRITE,
    )
    page[:] = b"\x90" * page_size
    exported = ctypes.c_char.from_buffer(page)
    base = ctypes.addressof(exported)
    del exported

    entry_offset = 0x100
    stub = bytearray()
    stub += b"\xf3\x0f\x1e\xfa"                         # ENDBR64
    stub += b"\x49\xbc" + struct.pack("<Q", heartbeat_address)
    stub += b"\xb8" + struct.pack("<I", SYS_WRITE)
    stub += b"\xbf" + struct.pack("<I", sync_write_fd)
    lea_at = len(stub)
    stub += b"\x48\x8d\x35\x00\x00\x00\x00"
    stub += b"\xba\x01\x00\x00\x00"
    stub += b"\x0f\x05"
    loop_offset = len(stub)
    stub += b"\xf0\x49\xff\x04\x24"                    # lock inc qword [r12]
    stub += b"\xf3\x90\xeb\xf7"                         # pause; jmp loop
    ready_offset = len(stub)
    stub += b"R"
    displacement = ready_offset - (lea_at + 7)
    struct.pack_into("<i", stub, lea_at + 3, displacement)
    page[entry_offset : entry_offset + len(stub)] = stub

    ctypes.set_errno(0)
    if _libc().mprotect(base, page_size, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
        saved_errno = ctypes.get_errno()
        page.close()
        raise LabError(f"mprotect(RX) failed: {os.strerror(saved_errno)}")

    entry = base + entry_offset
    loop_start = entry + loop_offset
    loop_end = loop_start + 9
    return page, base, entry, loop_start, loop_end


def child_main(
    entry: int,
    expected_parent: int,
    sync_read_fd: int,
    output_read_fd: int,
) -> None:
    try:
        os.close(sync_read_fd)
        os.close(output_read_fd)
        if _libc().prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(120)
        if os.getppid() != expected_parent:
            os._exit(121)
        ctypes.CFUNCTYPE(None)(entry)()
    except BaseException:
        os._exit(122)
    os._exit(123)


def _launch_sacrificial_child(
    entry: int,
    parent_pid: int,
    sync_read_fd: int,
    output_read_fd: int,
) -> _OwnedChild:
    pid = os.fork()
    if pid == 0:
        child_main(entry, parent_pid, sync_read_fd, output_read_fd)
    try:
        return _OwnedChild(pid, _CHILD_HANDLE_KEY)
    except BaseException:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        while True:
            try:
                os.waitpid(pid, 0)
                break
            except InterruptedError:
                continue
            except ChildProcessError:
                break
        raise


def _pipe_identity(
    child: _OwnedChild,
    child_write_fd: int,
    parent_read_fd: int,
) -> str:
    child.require_live()
    try:
        parent_pipe = os.readlink(f"/proc/self/fd/{parent_read_fd}")
        child_pipe = os.readlink(f"/proc/{child.pid}/fd/{child_write_fd}")
    except OSError as exc:
        raise LabError(
            f"cannot bind the inherited pipe to pid {child.pid}: {exc}"
        ) from exc
    if parent_pipe != child_pipe or not parent_pipe.startswith("pipe:["):
        raise LabError(
            f"pipe identity mismatch: parent={parent_pipe!r}, child={child_pipe!r}"
        )
    return parent_pipe


def _executable_mapping(child: _OwnedChild, address: int, length: int) -> str:
    if length <= 0:
        raise ValueError("mapping check requires a positive length")
    child.require_live()
    pid = child.pid
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="ascii") as maps_file:
            for line in maps_file:
                fields = line.rstrip("\n").split(maxsplit=5)
                if len(fields) < 5:
                    raise LabError(f"malformed /proc/{pid}/maps line: {line!r}")
                try:
                    lower_text, upper_text = fields[0].split("-", 1)
                    lower = int(lower_text, 16)
                    upper = int(upper_text, 16)
                except ValueError as exc:
                    raise LabError(f"malformed /proc/{pid}/maps range: {fields[0]!r}") from exc
                if not lower <= address < upper:
                    continue
                if address + length > upper:
                    raise LabError(
                        f"injection [0x{address:x}, 0x{address + length:x}) crosses "
                        f"mapping [0x{lower:x}, 0x{upper:x})"
                    )
                permissions = fields[1]
                if "r" not in permissions or "x" not in permissions or "w" in permissions:
                    raise LabError(
                        f"injection mapping has unsafe permissions {permissions!r}; "
                        "expected readable, executable, and non-writable"
                    )
                return permissions
    except OSError as exc:
        raise LabError(f"cannot inspect mappings for pid {pid}: {exc}") from exc
    raise LabError(f"injection address 0x{address:x} is absent from /proc/{pid}/maps")


def copy_registers(registers: UserRegsStruct) -> UserRegsStruct:
    duplicate = UserRegsStruct()
    ctypes.memmove(ctypes.byref(duplicate), ctypes.byref(registers), ctypes.sizeof(registers))
    return duplicate


def registers_bytes(registers: UserRegsStruct) -> bytes:
    return ctypes.string_at(ctypes.byref(registers), ctypes.sizeof(registers))


def _kill_and_reap(child: _OwnedChild, timeout: float) -> int | None:
    if child.reaped:
        return child.terminal_status
    child.send_signal(signal.SIGKILL, missing_ok=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status = child.wait(
                max(0.001, deadline - time.monotonic()),
                stopped=True,
            )
        except LabError:
            if child.reaped:
                return child.terminal_status
            raise
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            return status
        if os.WIFSTOPPED(status):
            try:
                _ptrace(PTRACE_CONT, child, 0, signal.SIGKILL)
            except LabError:
                pass
    raise LabError(f"could not reap sacrificial child {child.pid}")


def run_once(
    *,
    local_lab_acknowledged: bool = False,
    timeout: float = 3.0,
) -> RunResult:
    if local_lab_acknowledged is not True:
        raise LabError("run_once requires explicit local-lab acknowledgement")
    require_linux_x86_64()
    started = time.monotonic()
    parent_pid = os.getpid()
    sync_read = -1
    sync_write = -1
    output_read = -1
    output_write = -1
    page: mmap.mmap | None = None
    heartbeat_page: mmap.mmap | None = None
    child: _OwnedChild | None = None
    attached = False
    tracee_stopped = False
    patched = False
    registers_dirty = False
    detached = False
    saved_registers: UserRegsStruct | None = None
    saved_code: bytes | None = None
    injection_rip = 0
    child_output_fd = -1

    try:
        sync_read, sync_write = os.pipe2(os.O_CLOEXEC)
        output_read, output_write = os.pipe2(os.O_CLOEXEC)
        child_output_fd = output_write
        heartbeat_page, heartbeat_address = build_heartbeat_page()
        page, page_base, entry, loop_start, loop_end = build_spin_page(
            sync_write,
            heartbeat_address,
        )
        child = _launch_sacrificial_child(
            entry,
            parent_pid,
            sync_read,
            output_read,
        )
        child_pid = child.pid

        os.close(sync_write)
        sync_write = -1
        os.close(output_write)
        output_write = -1

        ready = read_exact_bounded(
            sync_read,
            1,
            timeout,
            label="child readiness byte",
            limit=1,
        )
        if ready != b"R":
            raise LabError(f"unexpected child readiness marker: {ready!r}")
        os.close(sync_read)
        sync_read = -1
        page.close()
        page = None

        child.require_live()
        pipe_name = _pipe_identity(child, child_output_fd, output_read)

        # output_write is intentionally closed in the tracer, but its numeric descriptor
        # remains the descriptor inherited by the child and embedded in the payload.
        nonce = secrets.token_hex(16)
        marker = f"ghostframe:{child_pid}:{nonce}\n".encode("ascii")
        payload, int3_offset = build_injected_writer(child_output_fd, marker)

        _ptrace(PTRACE_ATTACH, child)
        attached = True
        status = child.wait(timeout, stopped=True)
        _require_stop(child, status, signal.SIGSTOP)
        tracee_stopped = True

        current = _get_registers(child)
        saved_registers = copy_registers(current)
        injection_rip = current.rip
        if not loop_start <= injection_rip < loop_end:
            raise LabError(
                f"child stopped outside its spin stub: rip=0x{injection_rip:x}, "
                f"expected [0x{loop_start:x}, 0x{loop_end:x})"
            )
        if injection_rip + len(payload) > page_base + mmap.PAGESIZE:
            raise LabError("injection would cross the sacrificial executable page")
        mapping_permissions = _executable_mapping(child, injection_rip, len(payload))

        saved_code = _read_code(child, injection_rip, len(payload))
        patched = True
        _write_code(child, injection_rip, payload)
        if _read_code(child, injection_rip, len(payload)) != payload:
            raise LabError("ptrace write did not produce the requested code image")

        # From this point onward an async interruption must conservatively assume
        # the tracee ran and both its code and register state require restoration.
        registers_dirty = True
        tracee_stopped = False
        _ptrace(PTRACE_CONT, child)
        status = child.wait(timeout, stopped=True)
        _require_stop(child, status, signal.SIGTRAP)
        tracee_stopped = True

        trapped = _get_registers(child)
        expected_trap_rip = injection_rip + int3_offset + 1
        if trapped.rip != expected_trap_rip:
            raise LabError(
                f"unexpected trap RIP 0x{trapped.rip:x}; "
                f"expected 0x{expected_trap_rip:x}"
            )
        if trapped.rax != len(marker):
            signed_rax = ctypes.c_longlong(trapped.rax).value
            raise LabError(
                f"injected write returned {signed_rax}; expected {len(marker)}"
            )

        captured = read_exact_bounded(
            output_read,
            len(marker),
            timeout,
            label="injected marker",
            limit=MAX_CAPTURE,
        )
        if captured != marker:
            raise LabError(f"marker mismatch: expected {marker!r}, received {captured!r}")

        _write_code(child, injection_rip, saved_code)
        restored_code = _read_code(child, injection_rip, len(saved_code))
        code_restored = restored_code == saved_code
        if not code_restored:
            raise LabError("original executable bytes failed their read-back check")
        patched = False

        _set_registers(child, saved_registers)
        restored_registers = _get_registers(child)
        registers_restored = registers_bytes(restored_registers) == registers_bytes(
            saved_registers
        )
        if not registers_restored:
            raise LabError("original register image failed its read-back check")
        registers_dirty = False

        heartbeat_before = stable_heartbeat(heartbeat_page)
        if heartbeat_before == 0:
            raise LabError("spin stub never initialized its shared heartbeat")

        _ptrace(PTRACE_DETACH, child)
        attached = False
        tracee_stopped = False
        detached = True

        heartbeat_after = wait_for_heartbeat(heartbeat_page, heartbeat_before, timeout)
        heartbeat_delta = (heartbeat_after - heartbeat_before) & WORD_MASK
        if heartbeat_delta == 0:
            raise LabError("heartbeat did not advance after detach")

        child.send_signal(signal.SIGTERM)
        terminal_status = child.wait(timeout, stopped=False)
        if not os.WIFSIGNALED(terminal_status) or os.WTERMSIG(terminal_status) != signal.SIGTERM:
            raise LabError(
                f"sacrificial child ended with {describe_wait_status(terminal_status)}"
            )

        original_hash = hashlib.sha256(saved_code).hexdigest()
        restored_hash = hashlib.sha256(restored_code).hexdigest()
        register_hash = hashlib.sha256(registers_bytes(saved_registers)).hexdigest()
        return RunResult(
            child_pid=child_pid,
            nonce=nonce,
            marker=marker.decode("ascii").rstrip("\n"),
            pipe=pipe_name,
            injection_rip=f"0x{injection_rip:016x}",
            trap_rip=f"0x{trapped.rip:016x}",
            mapping_permissions=mapping_permissions,
            payload_bytes=len(payload),
            original_code_sha256=original_hash,
            restored_code_sha256=restored_hash,
            register_snapshot_sha256=register_hash,
            code_restored=code_restored,
            registers_restored=registers_restored,
            detached=detached,
            heartbeat_before=heartbeat_before,
            heartbeat_after=heartbeat_after,
            heartbeat_delta=heartbeat_delta,
            termination_signal=signal.Signals(os.WTERMSIG(terminal_status)).name,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
    finally:
        active_error = sys.exc_info()[1]
        cleanup_failures: list[str] = []
        try:
            if child is not None and not child.reaped:
                if attached and (patched or registers_dirty):
                    if not tracee_stopped:
                        try:
                            if child.send_signal(signal.SIGSTOP, missing_ok=True):
                                status = child.wait(0.5, stopped=True)
                                tracee_stopped = os.WIFSTOPPED(status)
                        except BaseException as exc:  # cleanup must continue
                            tracee_stopped = False
                            cleanup_failures.append(f"could not stop tracee: {exc}")

                    if (
                        tracee_stopped
                        and not child.reaped
                        and saved_registers is not None
                        and saved_code is not None
                    ):
                        try:
                            if patched:
                                _write_code(child, injection_rip, saved_code)
                                restored_code = _read_code(
                                    child,
                                    injection_rip,
                                    len(saved_code),
                                )
                                if restored_code != saved_code:
                                    raise LabError(
                                        "cleanup code restoration failed read-back"
                                    )
                                patched = False
                            if registers_dirty:
                                _set_registers(child, saved_registers)
                                restored = _get_registers(child)
                                if registers_bytes(restored) != registers_bytes(
                                    saved_registers
                                ):
                                    raise LabError(
                                        "cleanup register restoration failed read-back"
                                    )
                                registers_dirty = False
                        except BaseException as exc:  # keep a corrupt tracee attached
                            cleanup_failures.append(f"tracee restoration failed: {exc}")

                if (
                    attached
                    and tracee_stopped
                    and not child.reaped
                    and not patched
                    and not registers_dirty
                ):
                    try:
                        _ptrace(PTRACE_DETACH, child)
                        attached = False
                        tracee_stopped = False
                    except BaseException as exc:  # kill it while tracing remains active
                        cleanup_failures.append(f"tracee detach failed: {exc}")

                if not child.reaped:
                    try:
                        _kill_and_reap(child, 1.0)
                    except BaseException as exc:  # resources below still must close
                        cleanup_failures.append(f"child reap failed: {exc}")
        finally:
            for fd in (sync_read, sync_write, output_read, output_write):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except BaseException as exc:
                        cleanup_failures.append(f"close fd {fd} failed: {exc}")
            for label, mapping in (("code", page), ("heartbeat", heartbeat_page)):
                if mapping is not None:
                    try:
                        mapping.close()
                    except BaseException as exc:
                        cleanup_failures.append(f"close {label} mapping failed: {exc}")
            if child is not None:
                try:
                    child.close()
                except BaseException as exc:
                    cleanup_failures.append(f"close pidfd failed: {exc}")

        if cleanup_failures:
            cleanup_error = LabError("cleanup failed: " + "; ".join(cleanup_failures))
            if active_error is not None:
                raise cleanup_error from active_error
            raise cleanup_error


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="self-contained x86-64 ptrace injection lab",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--run-local-lab",
        action="store_true",
        help="explicitly permit creation and injection of the sacrificial child",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        metavar="N",
        help=f"run N fresh children (1-{MAX_REPEAT}; default: 1)",
    )
    args = parser.parse_args(argv)
    if not args.run_local_lab:
        parser.error("refusing to run without --run-local-lab")
    if not 1 <= args.repeat <= MAX_REPEAT:
        parser.error(f"--repeat must be between 1 and {MAX_REPEAT}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        require_linux_x86_64()
        results = [
            run_once(local_lab_acknowledged=True) for _ in range(args.repeat)
        ]
    except (LabError, OSError) as exc:
        print(f"ghostframe: {exc}", file=sys.stderr)
        return 1

    document = {
        "runs": [asdict(result) for result in results],
        "summary": {
            "completed": len(results),
            "unique_children": len({result.child_pid for result in results}),
            "unique_injection_rips": len({result.injection_rip for result in results}),
            "all_code_restored": all(result.code_restored for result in results),
            "all_registers_restored": all(result.registers_restored for result in results),
            "all_detached": all(result.detached for result in results),
            "all_rx_nonwritable": all(
                "r" in result.mapping_permissions
                and "x" in result.mapping_permissions
                and "w" not in result.mapping_permissions
                for result in results
            ),
            "all_heartbeats_advanced": all(
                result.heartbeat_delta > 0 for result in results
            ),
            "all_reaped_by_sigterm": all(
                result.termination_signal == "SIGTERM" for result in results
            ),
        },
    }
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
