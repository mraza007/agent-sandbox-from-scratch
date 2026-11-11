"""The host side of the test: what the attacks aim at, and what the harness can observe."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

import lab
import seccomp
from expected import Column
from policy import Policy
from syscalls import NR

HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX = os.path.join(HERE, "sandbox.py")
HOME = os.path.expanduser("~")
WORKSPACE = os.path.join(HOME, "project")
SCRATCH = os.path.join(HOME, "matrix-scratch")
REFERENCE = os.path.join(HOME, lab.REFERENCE)
SUBMOUNT = os.path.join(HOME, lab.SUBMOUNT)
LEAKED_FD = 20  # an open host directory that the launcher forgot to close
ENV_SECRET_NAME = "AGENT_API_TOKEN"

LAB_POLICY = {
    "workspace": WORKSPACE,
    "read_only": [*Policy(workspace=WORKSPACE).read_only, REFERENCE],
    "allowed_hosts": [lab.ALLOWED.name, lab.METADATA.name],
    "memory_bytes": 96 * 2**20,
    "cpus": 0.5,
    "max_pids": 32,
}
# How far the resource attacks go when nothing stops them. Safe without a sandbox.
FORK_CAP = 100
MEMORY_CAP_MB = 256
CPU_BURN_SECONDS = 1.0


def read(path: str) -> str:
    with open(path) as f:
        return f.read()


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def fake(kind: str) -> str:
    """A value that is new on every run, so a stale or guessed answer cannot pass."""
    return f"FAKE-{kind}-{secrets.token_hex(8)}"


@dataclass
class World:
    secret: str = field(default_factory=lambda: fake("AWS-KEY"))
    env_secret: str = field(default_factory=lambda: fake("API-TOKEN"))
    workspace_secret: str = field(default_factory=lambda: fake("DOTENV"))
    host_tmp_secret: str = field(default_factory=lambda: fake("TMP"))
    shm_secret: str = field(default_factory=lambda: fake("SHM"))
    marker: str = field(default_factory=lambda: fake("MARKER"))
    victim_marker: str = field(default_factory=lambda: fake("VICTIM"))
    shm_key: int = field(default_factory=lambda: 0x5B000000 + secrets.randbelow(2**20))
    servers: dict[str, lab.FakeServer] = field(default_factory=dict)
    host_service: lab.AbstractSocketService = field(
        default_factory=lambda: lab.AbstractSocketService(
            "agent-sandbox-lab-" + secrets.token_hex(4), fake("HOST-SERVICE")
        )
    )
    victim: subprocess.Popen | None = None

    secret_path = os.path.join(HOME, ".aws", "credentials")
    bashrc_path = os.path.join(HOME, ".bashrc")
    host_tmp_path = "/tmp/host-tmp-secret"
    planted_path = os.path.join(REFERENCE, "planted.txt")
    planted_in_submount = os.path.join(SUBMOUNT, "planted.txt")
    control_path = os.path.join(WORKSPACE, "control.txt")
    git_hook_path = os.path.join(WORKSPACE, ".git", "hooks", "pre-commit")
    log_path = os.path.join(SCRATCH, "sandbox.log")
    config_path = os.path.join(WORKSPACE, "attack-config.json")

    def build(self) -> None:
        write(self.secret_path, self.secret + "\n")
        write(self.host_tmp_path, self.host_tmp_secret + "\n")
        write(os.path.join(REFERENCE, "README"), "reference material\n")
        write(os.path.join(WORKSPACE, ".env"), self.workspace_secret + "\n")
        for script in ("attacks.py", "syscall_probe.py"):
            shutil.copy(os.path.join(HERE, script), WORKSPACE)

        home_directory = os.open(HOME, os.O_RDONLY | os.O_DIRECTORY)
        os.dup2(home_directory, LEAKED_FD, inheritable=False)
        self.host_service.start(home_directory)
        lab.share_memory(self.shm_key, self.shm_secret)
        for host in lab.HOSTS:
            self.servers[host.name] = lab.FakeServer(host, fake(host.name))
            self.servers[host.name].start()

    def attack_config(self, victim_pid: int) -> dict:
        return {
            "secret_path": self.secret_path,
            "secret_relative_to_home": os.path.relpath(self.secret_path, HOME),
            "host_tmp_path": self.host_tmp_path,
            "bashrc_path": self.bashrc_path,
            "read_only_dir": REFERENCE,
            "read_only_submount": SUBMOUNT,
            "leaked_fd": LEAKED_FD,
            "capability_binary": lab.CAPABILITY_BINARY,
            "marker": self.marker,
            "env_secret_name": ENV_SECRET_NAME,
            "victim_marker": self.victim_marker,
            "victim_pid": victim_pid,
            "shm_key": self.shm_key,
            "abstract_socket": self.host_service.name,
            "port": lab.PORT,
            "allowed_host": lab.ALLOWED.name,
            "denied_host": lab.DENIED.name,
            "denied_address": lab.DENIED.address,
            "rebind_host": lab.METADATA.name,
            "metadata_address": lab.METADATA.address,
            "max_pids": LAB_POLICY["max_pids"],
            "memory_bytes": LAB_POLICY["memory_bytes"],
            "fork_cap": FORK_CAP,
            "memory_cap_mb": MEMORY_CAP_MB,
            "cpu_burn_seconds": CPU_BURN_SECONDS,
            "denied_syscalls": {name: NR[name] for name in (*seccomp.DENIED, "clone3")},
        }

    def reset(self) -> None:
        """Undo whatever the last attack changed, so every cell starts the same."""
        write(self.bashrc_path, "# ~/.bashrc\n")
        write(self.log_path, "")
        if self.victim is None or self.victim.poll() is not None:
            self.victim = lab.spawn_victim(self.victim_marker)
            write(self.config_path, json.dumps(self.attack_config(self.victim.pid)))
        shutil.rmtree(os.path.join(WORKSPACE, ".git"), ignore_errors=True)
        for path in (self.control_path, self.planted_path, self.planted_in_submount):
            if os.path.exists(path):
                os.remove(path)
        for server in self.servers.values():
            server.probes.clear()
        self.host_service.connections = 0

    def run(
        self, column: Column, script: str, *args: str
    ) -> subprocess.CompletedProcess[str]:
        """Run one script from the workspace under one sandbox configuration."""
        self.reset()
        policy_path = os.path.join(SCRATCH, f"policy-{column.name}.json")
        write(policy_path, json.dumps(LAB_POLICY | column.policy_changes))
        command = [sys.executable, SANDBOX, *column.sandbox_args]
        command += ["--policy", policy_path, "--log", self.log_path]
        command += ["--", sys.executable, script, *args]
        return subprocess.run(
            command,
            cwd=WORKSPACE,
            env=os.environ | {ENV_SECRET_NAME: self.env_secret},
            stdin=subprocess.DEVNULL,
            pass_fds=[LEAKED_FD],
            capture_output=True,
            text=True,
            timeout=120,
        )

    def events(self, kind: str) -> list[dict]:
        """What the sandbox logged during the last run: proxy decisions, limit counters."""
        lines = [json.loads(line) for line in read(self.log_path).splitlines()]
        return [line for line in lines if line["event"] == kind]

    def reached(self, host: lab.Host, probe: str) -> bool:
        return probe in self.servers[host.name].probes

    def token(self, host: lab.Host) -> str:
        return self.servers[host.name].token

    def victim_pid(self) -> str:
        return str(self.victim.pid) if self.victim else ""

    def victim_died(self) -> bool:
        if self.victim is None:
            return False
        try:
            self.victim.wait(timeout=2)
        except subprocess.TimeoutExpired:
            return False
        return True

    def holds_marker(self, path: str) -> bool:
        """True if path exists, carries this run's marker, and belongs to the real user."""
        if not os.path.exists(path):
            return False
        return self.marker in read(path) and os.stat(path).st_uid == os.getuid()
