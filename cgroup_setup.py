#!/usr/bin/env python3
"""The one step that needs root: delegate a cgroup v2 subtree to an ordinary user.

    cgroup_setup.py USER PID

Creates /sys/fs/cgroup/agent-sandbox, owned by USER, with the memory, cpu and
pids controllers switched on, and moves PID (the shell that will launch
sandboxes) into its "session" leaf. After this, sandbox.py --level 6 creates
and removes its own cgroups without root.

A cgroup that holds processes cannot hand controllers to its children. Inside
a container the top cgroup holds processes, so they are moved to a leaf first.
"""

from __future__ import annotations

import errno
import os
import pwd
import sys

ROOT = "/sys/fs/cgroup"
SUBTREE = f"{ROOT}/agent-sandbox"
CONTROLLERS = ("memory", "pids", "cpu")


def read(path: str) -> str:
    with open(path) as f:
        return f.read()


def write(path: str, text: object) -> None:
    with open(path, "w") as f:
        f.write(str(text))


def move_processes(source: str, leaf: str) -> None:
    os.makedirs(leaf, exist_ok=True)
    for pid in read(f"{source}/cgroup.procs").split():
        write(f"{leaf}/cgroup.procs", pid)


def enable_controllers(cgroup: str) -> None:
    wanted = " ".join(f"+{name}" for name in CONTROLLERS)
    try:
        write(f"{cgroup}/cgroup.subtree_control", wanted)
    except OSError as error:
        if error.errno != errno.EBUSY:
            raise
        move_processes(cgroup, f"{cgroup}/init")
        write(f"{cgroup}/cgroup.subtree_control", wanted)


def delegate(cgroup: str, uid: int, gid: int) -> None:
    """Hand over the directory and the files the kernel lists as safe to delegate."""
    os.chown(cgroup, uid, gid)
    for name in read("/sys/kernel/cgroup/delegate").split():
        if os.path.exists(f"{cgroup}/{name}"):
            os.chown(f"{cgroup}/{name}", uid, gid)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    user, session_pid = pwd.getpwnam(sys.argv[1]), int(sys.argv[2])
    enable_controllers(ROOT)
    os.makedirs(SUBTREE, exist_ok=True)
    delegate(SUBTREE, user.pw_uid, user.pw_gid)
    enable_controllers(SUBTREE)
    os.makedirs(f"{SUBTREE}/session", exist_ok=True)
    delegate(f"{SUBTREE}/session", user.pw_uid, user.pw_gid)
    # A user may move a process only between cgroups it owns, so the launching
    # shell has to start out inside the delegated subtree.
    write(f"{SUBTREE}/session/cgroup.procs", session_pid)
    print(f"delegated {SUBTREE} to {user.pw_name}")


if __name__ == "__main__":
    main()
