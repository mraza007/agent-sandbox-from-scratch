#!/usr/bin/env python3
"""The hermetic test network: three fake hosts on the container's loopback device.

    lab.py setup USER   (as root, once per container)

No test leaves the container. Run it with --network none to prove that.
"""

from __future__ import annotations

import ctypes
import fcntl
import os
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = 80


@dataclass(frozen=True)
class Host:
    name: str
    address: str


# The addresses sit outside loopback so the proxy's default policy can reach
# "allowed". The metadata address is the real link-local one.
ALLOWED = Host("allowed.test", "10.80.0.10")
DENIED = Host("denied.test", "10.80.0.20")
METADATA = Host("rebind.test", "169.254.169.254")
HOSTS = (ALLOWED, DENIED, METADATA)

# A directory the user owns but the policy marks read-only, with a mount inside
# it, to check that "read-only" reaches submounts.
REFERENCE = "reference"
SUBMOUNT = "reference/mounted"

# A copy of cat that carries a file capability, the modern form of a setuid
# binary. Running it is how a process picks up privilege it did not start with.
CAPABILITY_BINARY = "/usr/local/bin/cat-with-capability"
CAP_NET_BIND_SERVICE = 10


def add_address(alias: str, address: str) -> None:
    SIOCSIFADDR, SIOCSIFNETMASK = 0x8916, 0x891C
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for request, value in (
            (SIOCSIFADDR, address),
            (SIOCSIFNETMASK, "255.255.255.255"),
        ):
            sockaddr = struct.pack("H2x4s8x", socket.AF_INET, socket.inet_aton(value))
            fcntl.ioctl(s, request, struct.pack("16s16s", alias.encode(), sockaddr))


def setup(user: pwd.struct_passwd) -> None:
    submount = os.path.join(user.pw_dir, SUBMOUNT)
    os.makedirs(submount, exist_ok=True)
    os.chown(os.path.dirname(submount), user.pw_uid, user.pw_gid)
    if not os.path.ismount(submount):
        owner = f"uid={user.pw_uid},gid={user.pw_gid}"
        subprocess.run(
            ["mount", "-t", "tmpfs", "-o", owner, "tmpfs", submount], check=True
        )
    shutil.copy("/usr/bin/cat", CAPABILITY_BINARY)
    # struct vfs_cap_data, revision 2, effective bit set: magic, then permitted
    # and inheritable as two 32-bit halves each.
    capability = struct.pack("<5I", 0x02000001, 1 << CAP_NET_BIND_SERVICE, 0, 0, 0)
    os.setxattr(CAPABILITY_BINARY, "security.capability", capability)
    with open("/etc/hosts") as f:
        known = f.read()
    with open("/etc/hosts", "a") as f:
        for number, host in enumerate(HOSTS, start=1):
            add_address(f"lo:{number}", host.address)
            if host.name not in known:
                f.write(f"{host.address} {host.name}\n")


@dataclass
class FakeServer:
    """An HTTP server that answers every GET with its token and records who asked."""

    host: Host
    token: str
    probes: list[str] = field(default_factory=list)

    def start(self) -> None:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                fake.probes += parse_qs(urlsplit(self.path).query).get("probe", ["?"])
                body = fake.token.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        server = ThreadingHTTPServer((self.host.address, PORT), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()


@dataclass
class AbstractSocketService:
    """A host service on an abstract Unix socket.

    It greets whoever connects with its token and passes them an open
    directory, the way real services hand file descriptors to their clients.
    """

    name: str
    token: str
    connections: int = 0

    def start(self, directory_fd: int) -> None:
        listener = socket.socket(socket.AF_UNIX)
        listener.bind("\0" + self.name)
        listener.listen()

        def serve() -> None:
            while True:
                client, _ = listener.accept()
                self.connections += 1
                with client:
                    socket.send_fds(client, [self.token.encode()], [directory_fd])

        threading.Thread(target=serve, daemon=True).start()


def share_memory(key: int, text: str) -> None:
    """Publish text in a System V shared memory segment, as a host IPC service would."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.shmat.restype = ctypes.c_void_p
    ipc_creat = 0o1000
    segment = libc.shmget(key, 4096, ipc_creat | 0o600)
    address = libc.shmat(segment, None, 0)
    if segment < 0 or address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), "could not create the shared memory segment")
    ctypes.memmove(address, text.encode() + b"\0", len(text) + 1)


def spawn_victim(marker: str) -> subprocess.Popen:
    """A host process for attacks to find and kill.

    Its PID is kept far above any PID a sandbox's own namespace reaches, so a
    signal aimed at it can never land on a process inside the sandbox instead.
    """
    while True:
        victim = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(3600)", marker]
        )
        if victim.pid > 1000:
            return victim
        victim.kill()
        victim.wait()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "setup":
        raise SystemExit(__doc__)
    setup(pwd.getpwnam(sys.argv[2]))
