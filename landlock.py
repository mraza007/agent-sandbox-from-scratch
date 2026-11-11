"""Landlock path rules through the three raw system calls."""

from __future__ import annotations

import errno
import os
import struct

from syscalls import no_new_privs, syscall

EXECUTE = 1 << 0
WRITE_FILE = 1 << 1
READ_FILE = 1 << 2
READ_DIR = 1 << 3
REMOVE_DIR = 1 << 4
REMOVE_FILE = 1 << 5
MAKE_CHAR = 1 << 6
MAKE_DIR = 1 << 7
MAKE_REG = 1 << 8
MAKE_SOCK = 1 << 9
MAKE_FIFO = 1 << 10
MAKE_BLOCK = 1 << 11
MAKE_SYM = 1 << 12
REFER = 1 << 13  # ABI 2
TRUNCATE = 1 << 14  # ABI 3
IOCTL_DEV = 1 << 15  # ABI 5

READ = EXECUTE | READ_FILE | READ_DIR
EVERYTHING = IOCTL_DEV * 2 - 1
# A rule on a file may carry only these. Any other right there is EINVAL.
FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV

CREATE_RULESET_VERSION = 1
RULE_PATH_BENEATH = 1


class Unavailable(Exception):
    pass


def abi_version() -> int:
    """Ask the running kernel which Landlock ABI it speaks."""
    try:
        return syscall("landlock_create_ruleset", None, 0, CREATE_RULESET_VERSION)
    except OSError as error:
        reasons = {
            errno.ENOSYS: "this kernel has no Landlock (it needs Linux 5.13 or newer)",
            errno.EOPNOTSUPP: "Landlock is built in but not enabled (see the lsm= boot parameter)",
        }
        reason = reasons.get(error.errno or 0, str(error))
        raise Unavailable(f"Landlock is not available: {reason}") from None


def rights_known_to(abi: int) -> int:
    """The filesystem rights that both this code and the kernel's ABI know."""
    rights = MAKE_SYM * 2 - 1
    if abi >= 2:
        rights |= REFER
    if abi >= 3:
        rights |= TRUNCATE
    if abi >= 5:
        rights |= IOCTL_DEV
    return rights


def restrict(rules: dict[str, int]) -> int:
    """Deny every handled right everywhere, except what rules ({path: rights}) allow.

    Returns the ABI version in use.
    """
    abi = abi_version()
    handled = rights_known_to(abi)
    ruleset = syscall("landlock_create_ruleset", struct.pack("Q", handled), 8, 0)
    for path, rights in rules.items():
        if not os.path.exists(path):
            continue
        rights &= handled if os.path.isdir(path) else handled & FILE_RIGHTS
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        # struct landlock_path_beneath_attr, packed: __u64 allowed_access; __s32 parent_fd;
        rule = struct.pack("=Qi", rights, fd)
        syscall("landlock_add_rule", ruleset, RULE_PATH_BENEATH, rule, 0)
        os.close(fd)
    no_new_privs()
    syscall("landlock_restrict_self", ruleset, 0)
    os.close(ruleset)
    return abi
