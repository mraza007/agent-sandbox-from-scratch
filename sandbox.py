#!/usr/bin/env python3
"""An agent sandbox built from Linux primitives, one layer per level.

    sandbox.py --level N [--policy FILE] [--log FILE] -- command [args...]

Level 0 runs the command as you. Each level above it adds one layer:

    1  rootless_start    user, PID, IPC and UTS namespaces
    2  new_root          mount namespace, bind mounts, pivot_root
    3  syscall_filter    no_new_privs and a seccomp-bpf denylist
    4  path_rules        Landlock
    5  private_network   empty network namespace, egress through a proxy
    6  resource_limits   cgroup v2 memory, CPU and pids limits

No level needs root. Level 6 needs a delegated cgroup: see cgroup_setup.py.
"""

from __future__ import annotations

import argparse
import enum
import fcntl
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading

import egress
import landlock
import seccomp
from policy import Policy
from syscalls import (
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    MNT_DETACH,
    MOUNT_ATTR_NODEV,
    MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_RDONLY,
    MS_BIND,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_PRIVATE,
    MS_REC,
    drop_capabilities,
    mount,
    mount_setattr,
    no_new_privs,
    pivot_root,
    umount2,
    unshare,
)

PROXY_SOCKET = "/run/egress.sock"
PROXY_PORT = 3128
CGROUP_ROOT = "/sys/fs/cgroup"
SETUP_FAILED = 125


class Layer(enum.IntEnum):
    ROOTLESS_START = 1
    NEW_ROOT = 2
    SYSCALL_FILTER = 3
    PATH_RULES = 4
    PRIVATE_NETWORK = 5
    RESOURCE_LIMITS = 6


REQUIRES = {
    Layer.NEW_ROOT: {Layer.ROOTLESS_START},
    Layer.PRIVATE_NETWORK: {Layer.ROOTLESS_START, Layer.NEW_ROOT},
}


class SandboxError(Exception):
    pass


def write(path: str, text: object) -> None:
    with open(path, "w") as f:
        f.write(str(text))


def exit_code(status: int) -> int:
    code = os.waitstatus_to_exitcode(status)
    return code if code >= 0 else 128 - code


def rootless_start() -> None:
    """Level 1. Become the only user in a new user namespace. Returns as PID 1."""
    uid, gid = os.getuid(), os.getgid()
    unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS)
    # An unprivileged process may map exactly one id: its own.
    write("/proc/self/uid_map", f"{uid} {uid} 1")
    write("/proc/self/setgroups", "deny")
    write("/proc/self/gid_map", f"{gid} {gid} 1")
    socket.sethostname("sandbox")
    # A new PID namespace starts with the next child, so fork to become its PID 1.
    child = os.fork()
    if child:
        _, status = os.waitpid(child, 0)
        os._exit(exit_code(status))


def bind(source: str, target: str, attributes: int) -> None:
    if os.path.islink(source):  # /bin is a symlink to usr/bin on merged-usr systems
        os.symlink(os.readlink(source), target)
        return
    if os.path.isdir(source):
        os.makedirs(target, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "a"):
            pass
    # MS_REC is not optional here: inside a user namespace the kernel refuses
    # to bind a tree and leave its submounts behind.
    mount(source, target, None, MS_BIND | MS_REC)
    if attributes:
        mount_setattr(target, attributes, recursive=True)


def new_root(policy: Policy, stage: str, proxy_socket: str | None) -> None:
    """Level 2. Build a root that holds only what the policy names, then pivot into it."""
    unshare(CLONE_NEWNS)
    # Private propagation: no mount event crosses between the host and us.
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    root = os.path.join(stage, "root")
    mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, "mode=755")

    locked_down = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV
    for path in policy.read_only:
        if os.path.lexists(path):
            bind(path, root + path, locked_down | MOUNT_ATTR_RDONLY)
    bind(policy.workspace, root + policy.workspace, locked_down)

    for directory in ("/tmp", "/proc", "/dev", "/run"):
        os.makedirs(root + directory, exist_ok=True)
    mount("tmpfs", root + "/tmp", "tmpfs", MS_NOSUID | MS_NODEV)
    mount("proc", root + "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    # mknod is not allowed in a user namespace, so borrow the host's device nodes.
    for device in ("null", "zero", "full", "random", "urandom", "tty"):
        bind(f"/dev/{device}", f"{root}/dev/{device}", MOUNT_ATTR_NOSUID)
    os.symlink("/proc/self/fd", root + "/dev/fd")
    if proxy_socket:
        bind(proxy_socket, root + PROXY_SOCKET, 0)

    os.chdir(root)
    pivot_root(".", ".")  # the old root is now stacked on top of the new one
    umount2(".", MNT_DETACH)
    os.chdir("/")
    mount_setattr("/", MOUNT_ATTR_RDONLY)
    os.chdir(policy.workspace)


def syscall_filter() -> None:
    """Level 3. Give up new privileges for good, then load the seccomp denylist."""
    no_new_privs()
    seccomp.install(seccomp.build_filter())


def path_rules(policy: Policy) -> None:
    """Level 4. Landlock: read the system paths, write the workspace, nothing else."""
    rules = {path: landlock.READ for path in policy.read_only}
    rules["/proc"] = landlock.READ
    rules["/dev"] = landlock.READ_FILE | landlock.WRITE_FILE | landlock.IOCTL_DEV
    rules["/tmp"] = landlock.EVERYTHING
    rules[policy.workspace] = landlock.EVERYTHING
    try:
        landlock.restrict(rules)
    except landlock.Unavailable as error:
        raise SandboxError(str(error)) from None


def loopback_up() -> None:
    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        request = struct.pack("16sH14x", b"lo", 0)
        (flags,) = struct.unpack_from("H", fcntl.ioctl(s, SIOCGIFFLAGS, request), 16)
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", flags | IFF_UP))


def private_network() -> socket.socket:
    """Level 5. A network namespace with only loopback. Returns the relay's listener."""
    unshare(CLONE_NEWNET)
    loopback_up()
    proxy = f"http://127.0.0.1:{PROXY_PORT}"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ[name] = proxy
    # Bind now, while we may. The relay itself starts later, with no privileges left.
    return socket.create_server(("127.0.0.1", PROXY_PORT))


def own_cgroup() -> str:
    with open("/proc/self/cgroup") as f:
        return CGROUP_ROOT + f.read().strip().rpartition("::")[2]


def sandbox_cgroup(pid: int) -> str:
    """Each sandbox gets a sibling of the cgroup its launcher lives in."""
    return os.path.join(os.path.dirname(own_cgroup()), f"sandbox-{pid}")


def resource_limits(policy: Policy) -> None:
    """Level 6. Create a cgroup, set its limits, and move into it."""
    cgroup = sandbox_cgroup(os.getpid())
    try:
        os.mkdir(cgroup)
        write(f"{cgroup}/memory.max", policy.memory_bytes)
        write(f"{cgroup}/memory.swap.max", 0)  # or the limit just pushes pages to swap
        write(f"{cgroup}/pids.max", policy.max_pids)
        write(f"{cgroup}/cpu.max", f"{int(policy.cpus * 100_000)} 100000")
        write(f"{cgroup}/cgroup.procs", os.getpid())
    except OSError as error:
        raise SandboxError(
            f"no usable delegated cgroup ({error}). Run cgroup_setup.py as root once."
        ) from None


def limits_report(cgroup: str) -> dict:
    """How often the kernel had to enforce each limit, read before the cgroup is removed."""

    def counter(file: str, key: str) -> int:
        with open(f"{cgroup}/{file}") as f:
            return int(dict(line.split() for line in f)[key])

    return {
        "event": "limits",
        "memory.events.oom_kill": counter("memory.events", "oom_kill"),
        "pids.events.max": counter("pids.events", "max"),
        "cpu.stat.nr_throttled": counter("cpu.stat", "nr_throttled"),
    }


def init(command: list[str], relay_listener: socket.socket | None) -> int:
    """PID 1 of the sandbox. Start the relay, run the command, reap what it leaves."""
    if relay_listener:
        if os.fork() == 0:
            try:
                egress.relay(relay_listener, PROXY_SOCKET)
            finally:
                os._exit(1)
        relay_listener.close()
    command_pid = os.fork()
    if command_pid == 0:
        # An open directory from the launcher would be a door back to the host's files.
        os.closerange(3, os.sysconf("SC_OPEN_MAX"))
        try:
            os.execvp(command[0], command)
        except OSError as error:
            print(f"sandbox: {command[0]}: {error.strerror}", file=sys.stderr)
            os._exit(127)
    while True:
        pid, status = os.wait()
        if pid == command_pid:
            return exit_code(status)


def enter(
    policy: Policy,
    layers: frozenset[Layer],
    command: list[str],
    stage: str,
    proxy_socket: str | None,
) -> None:
    """Apply the layers in the order the kernel demands, then run the command.

    Never returns: it ends in exec or in exit.
    """
    relay_listener = None
    try:
        if Layer.RESOURCE_LIMITS in layers:
            resource_limits(policy)  # first: new_root hides /sys/fs/cgroup
        if Layer.ROOTLESS_START in layers:
            rootless_start()
        if Layer.NEW_ROOT in layers:
            new_root(policy, stage, proxy_socket)
        if Layer.PRIVATE_NETWORK in layers:
            relay_listener = private_network()
        if Layer.ROOTLESS_START in layers:
            drop_capabilities()  # the namespaces are built; nothing below needs them
        if Layer.SYSCALL_FILTER in layers:
            syscall_filter()  # after new_root: the filter denies mount and pivot_root
        if Layer.PATH_RULES in layers:
            path_rules(policy)  # after new_root: Landlock also forbids mounting
        if Layer.ROOTLESS_START in layers:
            os._exit(init(command, relay_listener))
        os.execvp(command[0], command)
    except (OSError, SandboxError) as error:
        print(f"sandbox: {error}", file=sys.stderr)
        os._exit(SETUP_FAILED)


def event_log(path: str | None) -> egress.Log:
    """One JSON line per proxy decision or limit report, to a file or to stderr."""
    lock = threading.Lock()

    def log(event: dict) -> None:
        with lock:
            if path:
                with open(path, "a") as f:
                    f.write(json.dumps(event) + "\n")
            else:
                print(json.dumps(event), file=sys.stderr, flush=True)

    return log


def run(
    policy: Policy, layers: frozenset[Layer], command: list[str], log: egress.Log
) -> int:
    """The supervisor. It stays outside the sandbox and owns everything host-side."""
    stage = tempfile.mkdtemp(prefix="sandbox-")
    os.mkdir(os.path.join(stage, "root"))
    listener = proxy_socket = None
    if Layer.PRIVATE_NETWORK in layers:
        proxy_socket = os.path.join(stage, "egress.sock")
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(proxy_socket)
        listener.listen()

    child = os.fork()
    if child == 0:
        enter(policy, layers, command, stage, proxy_socket)
    if listener:
        # Started after the fork, so the child never inherits a lock held by this thread.
        threading.Thread(
            target=egress.serve, args=(listener, policy, log), daemon=True
        ).start()
    _, status = os.waitpid(child, 0)

    if Layer.RESOURCE_LIMITS in layers and os.path.isdir(sandbox_cgroup(child)):
        log(limits_report(sandbox_cgroup(child)))
        os.rmdir(sandbox_cgroup(child))
    shutil.rmtree(stage)
    return exit_code(status)


def parse_layers(level: int | None, layers: str | None) -> frozenset[Layer]:
    if layers is not None:
        chosen = frozenset(Layer(int(number)) for number in layers.split(",") if number)
    else:
        chosen = frozenset(layer for layer in Layer if layer <= (level or 0))
    for layer in chosen:
        missing = REQUIRES.get(layer, set()) - chosen
        if missing:
            names = ", ".join(m.name.lower() for m in sorted(missing))
            raise SystemExit(f"sandbox: {layer.name.lower()} needs {names}")
    return chosen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    which = parser.add_mutually_exclusive_group()
    which.add_argument(
        "--level", type=int, choices=range(7), help="apply layers 1 to N"
    )
    which.add_argument("--layers", help="apply exactly these layers, for example 3,4")
    parser.add_argument(
        "--policy", help="JSON policy file (default: the current directory)"
    )
    parser.add_argument("--log", help="write proxy decisions and limit events here")
    parser.add_argument("command", nargs="+")
    args = parser.parse_args()

    if os.geteuid() == 0:
        raise SystemExit(
            "sandbox: run me as an ordinary user. Only cgroup_setup.py needs root."
        )
    layers = parse_layers(args.level, args.layers)
    if args.policy:
        policy = Policy.from_json(args.policy)
    else:
        policy = Policy(workspace=os.getcwd())
    return run(policy, layers, args.command, event_log(args.log))


if __name__ == "__main__":
    sys.exit(main())
