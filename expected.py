"""The expected result of every attack at every level. Data only: edit claims here."""

from __future__ import annotations

from dataclasses import dataclass, field

from sandbox import Layer


@dataclass(frozen=True)
class Expect:
    outcome: str  # "allowed", "blocked" or "n/a"
    error: str | None = None
    detail: str | None = None  # checked only when set


ALLOWED = Expect("allowed")
NO_PROXY_YET = Expect("n/a")
NO_CAPABILITIES = "CapEff 0000000000000000"


def blocked(error: str, detail: str | None = None) -> Expect:
    return Expect("blocked", error, detail)


# attack -> {level where a result starts: the result}. It holds until the next entry.
EXPECTED: dict[str, dict[int, Expect]] = {
    # Files outside the workspace
    "read_secret": {0: ALLOWED, 2: blocked("ENOENT")},
    "read_secret_dotdot": {0: ALLOWED, 2: blocked("ENOENT")},
    "read_host_tmp": {0: ALLOWED, 2: blocked("ENOENT")},
    "write_outside": {0: ALLOWED, 2: blocked("EROFS")},
    "write_read_only_path": {0: ALLOWED, 2: blocked("EROFS")},
    "write_read_only_submount": {0: ALLOWED, 2: blocked("EROFS")},
    "inherited_fd": {0: ALLOWED, 1: blocked("EBADF")},
    "fd_from_host_service": {
        0: ALLOWED,
        4: blocked("EACCES"),
        5: blocked("ECONNREFUSED"),
    },
    # Other processes on the host
    "list_host_processes": {0: ALLOWED, 2: blocked("not-visible")},
    "kill_host_process": {0: ALLOWED, 1: blocked("ESRCH")},
    "sysv_shm": {0: ALLOWED, 1: blocked("ENOENT")},
    "abstract_socket": {0: ALLOWED, 5: blocked("ECONNREFUSED")},
    # The network
    "direct_tcp": {0: ALLOWED, 5: blocked("ENETUNREACH")},
    "proxy_denied_host": {0: NO_PROXY_YET, 5: blocked("403 host-not-allowed")},
    "metadata_direct": {0: ALLOWED, 5: blocked("ENETUNREACH")},
    "metadata_via_proxy": {0: NO_PROXY_YET, 5: blocked("403 address-denied")},
    # The kernel surface
    "mount": {
        0: blocked("EPERM", "missing-target probe: ENOENT"),
        3: blocked("EPERM", "missing-target probe: EPERM"),
    },
    "userns_mount": {0: ALLOWED, 3: blocked("EPERM")},
    "userns_unshare": {0: ALLOWED, 3: blocked("EPERM")},
    "userns_clone": {0: ALLOWED, 3: blocked("EPERM")},
    "userns_clone3": {0: ALLOWED, 3: blocked("ENOSYS")},
    "file_capabilities": {0: ALLOWED, 2: blocked("no-capabilities")},
    "ptrace": {0: ALLOWED, 3: blocked("EPERM")},
    "io_uring_setup": {0: ALLOWED, 3: blocked("EPERM")},
    "keyctl": {0: ALLOWED, 3: blocked("EPERM")},
    # Resources
    "fork_bomb": {0: ALLOWED, 6: blocked("EAGAIN")},
    "memory_hog": {0: ALLOWED, 6: blocked("SIGKILL")},
    "cpu_hog": {0: ALLOWED, 6: blocked("throttled")},
    # Positive controls: these must keep working.
    "ctl_workspace_write": {0: ALLOWED},
    "ctl_tmp_write": {0: ALLOWED},
    "ctl_system_read": {0: ALLOWED},
    "ctl_dev": {0: ALLOWED},
    "ctl_subprocess": {0: ALLOWED},
    "ctl_thread": {0: ALLOWED},
    "ctl_hostname": {0: ALLOWED, 1: Expect("allowed", detail="sandbox")},
    "ctl_parent_capabilities": {0: Expect("allowed", detail=NO_CAPABILITIES)},
    "ctl_proxy_allowed": {0: NO_PROXY_YET, 5: ALLOWED},
    # Known gaps: no layer here stops these.
    "gap_env_secret": {0: ALLOWED},
    "gap_workspace_secret": {0: ALLOWED},
    "gap_git_hook": {0: ALLOWED},
}


@dataclass(frozen=True)
class Column:
    """One way to run the sandbox, and how its results differ from a plain level."""

    name: str
    sandbox_args: tuple[str, ...]
    like_level: int
    overrides: dict[str, Expect] = field(default_factory=dict)
    policy_changes: dict = field(default_factory=dict)

    def expect(self, attack: str) -> Expect:
        if attack in self.overrides:
            return self.overrides[attack]
        phases = EXPECTED[attack]
        return phases[max(level for level in phases if level <= self.like_level)]


LEVELS = [Column(f"L{n}", ("--level", str(n)), like_level=n) for n in range(7)]

FILTER_REFUSES = blocked("EPERM")

ABLATIONS = [
    # no_new_privs and seccomp with no namespaces at all: what level 3 does on its own.
    Column(
        "filter-only",
        ("--layers", str(int(Layer.SYSCALL_FILTER))),
        like_level=0,
        overrides={
            "mount": blocked("EPERM", "missing-target probe: EPERM"),
            "userns_mount": FILTER_REFUSES,
            "userns_unshare": FILTER_REFUSES,
            "userns_clone": FILTER_REFUSES,
            "userns_clone3": blocked("ENOSYS"),
            "ptrace": FILTER_REFUSES,
            "io_uring_setup": FILTER_REFUSES,
            "keyctl": FILTER_REFUSES,
            "file_capabilities": blocked("no-capabilities"),
        },
    ),
    # Landlock with no namespaces at all: what level 4 does on its own.
    Column(
        "landlock-only",
        ("--layers", str(int(Layer.PATH_RULES))),
        like_level=0,
        overrides={
            "read_secret": blocked("EACCES"),
            "read_secret_dotdot": blocked("EACCES"),
            "write_outside": blocked("EACCES"),
            "write_read_only_path": blocked("EACCES"),
            "write_read_only_submount": blocked("EACCES"),
            "inherited_fd": blocked("EACCES"),
            "fd_from_host_service": blocked("EACCES"),
            # Refused at the write to /proc/self/uid_map: the rules make /proc read-only.
            "userns_mount": blocked("EACCES"),
            # Landlock needs no_new_privs, and that alone disarms the binary.
            "file_capabilities": blocked("no-capabilities"),
        },
    ),
    # Level 5 with the proxy's address check off: the rebinding attack must get through.
    Column(
        "L5-no-address-check",
        ("--level", "5"),
        like_level=5,
        overrides={"metadata_via_proxy": ALLOWED},
        policy_changes={"denied_networks": []},
    ),
]

BLOCKED_BY = {0: "the kernel, before any layer"} | {
    int(layer): f"L{int(layer)} {layer.name.lower()}" for layer in Layer
}
