"""Linux system calls that Python's os module does not wrap, called through libc."""

from __future__ import annotations

import ctypes
import os

# Syscall numbers are per architecture. Only the aarch64 column has been run.
# fmt: off
_NUMBERS = {
    #                          aarch64  x86_64
    "umount2":                 (39,     166),
    "mount":                   (40,     165),
    "pivot_root":              (41,     155),
    "capset":                  (91,     126),
    "unshare":                 (97,     272),
    "ptrace":                  (117,    101),
    "add_key":                 (217,    248),
    "request_key":             (218,    249),
    "keyctl":                  (219,    250),
    "clone":                   (220,    56),
    "setns":                   (268,    308),
    "process_vm_readv":        (270,    310),
    "process_vm_writev":       (271,    311),
    "seccomp":                 (277,    317),
    "bpf":                     (280,    321),
    "io_uring_setup":          (425,    425),
    "io_uring_enter":          (426,    426),
    "io_uring_register":       (427,    427),
    "open_tree":               (428,    428),
    "move_mount":              (429,    429),
    "fsopen":                  (430,    430),
    "fsconfig":                (431,    431),
    "fsmount":                 (432,    432),
    "fspick":                  (433,    433),
    "clone3":                  (435,    435),
    "mount_setattr":           (442,    442),
    "landlock_create_ruleset": (444,    444),
    "landlock_add_rule":       (445,    445),
    "landlock_restrict_self":  (446,    446),
}
# fmt: on

# AUDIT_ARCH_* is the value seccomp reports for the calling convention in use.
AUDIT_ARCH_AARCH64 = 0xC00000B7
AUDIT_ARCH_X86_64 = 0xC000003E
_ARCHES = {"aarch64": (0, AUDIT_ARCH_AARCH64), "x86_64": (1, AUDIT_ARCH_X86_64)}

MACHINE = os.uname().machine
if MACHINE not in _ARCHES:
    raise ImportError(f"no syscall table for {MACHINE}")
_column, AUDIT_ARCH = _ARCHES[MACHINE]
NR = {name: numbers[_column] for name, numbers in _NUMBERS.items()}

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

MS_NOSUID = 0x2
MS_NODEV = 0x4
MS_NOEXEC = 0x8
MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 0x40000
MNT_DETACH = 0x2

AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 0x1
MOUNT_ATTR_NOSUID = 0x2
MOUNT_ATTR_NODEV = 0x4

PR_SET_NO_NEW_PRIVS = 38

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def syscall(name: str, *args: object) -> int:
    """Make a raw system call. Raise OSError with the kernel's errno when it fails."""
    # ctypes passes a bare Python int as a 32-bit C int, which truncates flags and pointers.
    wide = [ctypes.c_long(arg) if isinstance(arg, int) else arg for arg in args]
    result = _libc.syscall(ctypes.c_long(NR[name]), *wide)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, f"{name}: {os.strerror(error)}")
    return result


def _encode(text: str | None) -> bytes | None:
    return None if text is None else os.fsencode(text)


def unshare(flags: int) -> None:
    if hasattr(os, "unshare"):  # Python 3.12 and newer
        os.unshare(flags)
    else:
        syscall("unshare", flags)


def mount(
    source: str | None,
    target: str,
    fstype: str | None,
    flags: int = 0,
    data: str | None = None,
) -> None:
    names = [_encode(source), _encode(target), _encode(fstype)]
    try:
        syscall("mount", *names, flags, _encode(data))
    except OSError as error:
        what = f"mount {source or fstype or 'flags'} on {target}"
        raise OSError(error.errno, f"{what}: {os.strerror(error.errno or 0)}") from None


def umount2(target: str, flags: int) -> None:
    syscall("umount2", _encode(target), flags)


def pivot_root(new_root: str, put_old: str) -> None:
    syscall("pivot_root", _encode(new_root), _encode(put_old))


def mount_setattr(path: str, set_attrs: int, recursive: bool = False) -> None:
    """Set mount attributes without restating the ones already there."""
    # struct mount_attr { __u64 attr_set, attr_clr, propagation, userns_fd; }
    attr = ctypes.create_string_buffer(set_attrs.to_bytes(8, "little") + bytes(24), 32)
    flags = AT_RECURSIVE if recursive else 0
    syscall("mount_setattr", AT_FDCWD, _encode(path), flags, attr, 32)


def no_new_privs() -> None:
    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"prctl(PR_SET_NO_NEW_PRIVS): {os.strerror(error)}")


def drop_capabilities() -> None:
    """Empty the effective, permitted and inheritable capability sets of this process."""
    linux_capability_version_3 = 0x20080522
    header = ctypes.create_string_buffer(
        linux_capability_version_3.to_bytes(4, "little") + bytes(4), 8
    )
    no_capabilities = ctypes.create_string_buffer(24)
    syscall("capset", header, no_capabilities)
