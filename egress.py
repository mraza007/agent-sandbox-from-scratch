"""The only way out of the sandbox: a CONNECT proxy on the host, and a relay inside."""

from __future__ import annotations

import ipaddress
import select
import socket
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass

from policy import Policy

Log = Callable[[dict], None]


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    host: str
    port: int
    address: str = ""


def decide(policy: Policy, host: str, port: int) -> Decision:
    """Allow by name, then refuse if the name resolves into a denied network."""
    name = host.rstrip(".").lower()
    if name not in policy.allowed_hosts:
        return Decision(False, "host-not-allowed", name, port)
    try:
        answers = socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return Decision(False, "resolve-failed", name, port)
    addresses = [ipaddress.ip_address(answer[4][0]) for answer in answers]
    for address in addresses:
        plain = getattr(address, "ipv4_mapped", None) or address
        if any(plain in network for network in policy.denied_networks):
            return Decision(False, "address-denied", name, port, str(plain))
    # The proxy connects to this address, not to the name, so a second
    # lookup cannot return something the check never saw.
    return Decision(True, "allowed", name, port, str(addresses[0]))


def read_head(connection: socket.socket) -> tuple[bytes, bytes]:
    """Read an HTTP head. Return it and any bytes that arrived after its blank line."""
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


def pump(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until either side closes."""
    with a, b:
        while True:
            readable, _, _ = select.select([a, b], [], [])
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (b if source is a else a).sendall(data)


def refuse(client: socket.socket, status: str) -> None:
    with client:
        client.sendall(f"HTTP/1.1 {status}\r\n\r\n".encode())


def handle(client: socket.socket, policy: Policy, log: Log) -> None:
    head, early_data = read_head(client)
    try:
        method, target, _ = head.split(b"\r\n")[0].decode("ascii").split(" ")
        host, _, port_text = target.rpartition(":")
        host, port = host.strip("[]"), int(port_text)
    except ValueError:
        log({"event": "egress", "allow": False, "reason": "bad-request"})
        return refuse(client, "400 bad-request")
    if method == "CONNECT":
        decision = decide(policy, host, port)
    else:
        decision = Decision(False, "method-not-allowed", host, port)
    log({"event": "egress", **asdict(decision)})
    if not decision.allow:
        return refuse(client, f"403 {decision.reason}")
    try:
        upstream = socket.create_connection((decision.address, port), timeout=10)
    except OSError as error:
        log(
            {
                "event": "egress-connect-failed",
                "host": decision.host,
                "error": str(error),
            }
        )
        return refuse(client, "502 connect-failed")
    upstream.settimeout(None)
    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    upstream.sendall(early_data)
    pump(client, upstream)


def serve(listener: socket.socket, policy: Policy, log: Log) -> None:
    """Host side. Accept on the Unix socket and decide each CONNECT against the policy."""
    while True:
        client, _ = listener.accept()
        threading.Thread(target=handle, args=(client, policy, log), daemon=True).start()


def relay(listener: socket.socket, proxy_socket: str) -> None:
    """Sandbox side. Forward 127.0.0.1 connections to the proxy's Unix socket."""
    while True:
        client, _ = listener.accept()
        upstream = socket.socket(socket.AF_UNIX)
        upstream.connect(proxy_socket)
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
