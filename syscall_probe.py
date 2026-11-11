#!/usr/bin/env python3
"""Call each syscall the filter denies, with all-zero arguments, and print the errno.

    syscall_probe.py        (reads ./attack-config.json)

Zero arguments are harmless but still get past the syscall entry point. Without
the filter most of these calls fail on the arguments (EFAULT, EINVAL, EBADF).
With it they fail with the filter's own errno, which shows the rule is live.
Each call runs in a throwaway child. Prints one JSON line per syscall.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

with open("attack-config.json") as config_file:
    DENIED_SYSCALLS: dict[str, int] = json.load(config_file)["denied_syscalls"]


def errno_of(number: int) -> str:
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        zero = ctypes.c_long(0)
        result = libc.syscall(ctypes.c_long(number), zero, zero, zero, zero, zero, zero)
        answer = errno.errorcode[ctypes.get_errno()] if result < 0 else "no error"
        os.write(writer, answer.encode())
        os._exit(0)
    os.close(writer)
    with os.fdopen(reader) as pipe:
        answer = pipe.read()
    os.waitpid(pid, 0)
    return answer or "child died"


for name, number in DENIED_SYSCALLS.items():
    print(json.dumps({"syscall": name, "errno": errno_of(number)}))
