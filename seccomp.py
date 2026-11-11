"""A seccomp-bpf filter assembled by hand: no libseccomp."""

from __future__ import annotations

import ctypes
import errno
import struct

from syscalls import AUDIT_ARCH, AUDIT_ARCH_X86_64, CLONE_NEWUSER, NR, syscall

# Always refused with EPERM.
# fmt: off
DENIED = (
    "mount", "umount2", "pivot_root",
    "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
    "ptrace", "process_vm_readv", "process_vm_writev",
    "bpf",
    "keyctl", "add_key", "request_key",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "setns",
)
# fmt: on
# Refused only when the flags in the first argument ask for a new user namespace.
DENIED_WITH_CLONE_NEWUSER = ("unshare", "clone")

# struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
OFFSET_NR = 0
OFFSET_ARCH = 4
OFFSET_ARG0 = 16  # the low 32 bits, on a little-endian machine

LOAD = 0x20  # BPF_LD | BPF_W | BPF_ABS
JEQ = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
JGE = 0x35  # BPF_JMP | BPF_JGE | BPF_K
JSET = 0x45  # BPF_JMP | BPF_JSET | BPF_K
RET = 0x06  # BPF_RET | BPF_K

ALLOW = 0x7FFF0000
KILL_PROCESS = 0x80000000
X32_SYSCALL_BIT = 0x40000000


def refuse(error: int) -> int:
    return 0x00050000 | error  # SECCOMP_RET_ERRNO


def instruction(
    code: int, k: int, skip_if_true: int = 0, skip_if_false: int = 0
) -> bytes:
    """One struct sock_filter. A jump says how many instructions to skip."""
    return struct.pack("HBBI", code, skip_if_true, skip_if_false, k)


def build_filter() -> bytes:
    """Return the filter program. Each rule starts with the syscall number loaded."""
    program = [
        instruction(LOAD, OFFSET_ARCH),
        instruction(JEQ, AUDIT_ARCH, 1, 0),
        instruction(RET, KILL_PROCESS),
        instruction(LOAD, OFFSET_NR),
    ]
    if AUDIT_ARCH == AUDIT_ARCH_X86_64:
        # The x32 ABI shares this AUDIT_ARCH. Its numbers would slip past the rules below.
        program += [
            instruction(JGE, X32_SYSCALL_BIT, 0, 1),
            instruction(RET, refuse(errno.EPERM)),
        ]
    for name in DENIED:
        program += [
            instruction(JEQ, NR[name], 0, 1),
            instruction(RET, refuse(errno.EPERM)),
        ]
    for name in DENIED_WITH_CLONE_NEWUSER:
        program += [
            instruction(JEQ, NR[name], 0, 4),
            instruction(LOAD, OFFSET_ARG0),
            instruction(JSET, CLONE_NEWUSER, 0, 1),
            instruction(RET, refuse(errno.EPERM)),
            instruction(LOAD, OFFSET_NR),
        ]
    # clone3 passes its flags in a struct that BPF cannot read.
    # ENOSYS makes glibc fall back to clone, which the rule above can check.
    program += [
        instruction(JEQ, NR["clone3"], 0, 1),
        instruction(RET, refuse(errno.ENOSYS)),
        instruction(RET, ALLOW),
    ]
    return b"".join(program)


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install(program: bytes) -> None:
    """Load the filter for this thread and everything it forks or execs."""
    buffer = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // 8, ctypes.addressof(buffer))
    seccomp_set_mode_filter = 1
    syscall("seccomp", seccomp_set_mode_filter, 0, ctypes.byref(fprog))
