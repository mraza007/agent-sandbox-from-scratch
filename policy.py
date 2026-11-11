"""The one data shape every layer reads."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, fields, replace

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

LOOPBACK_AND_LINK_LOCAL = ("127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10")


def parse_networks(networks: list[str] | tuple[str, ...]) -> tuple[Network, ...]:
    return tuple(ipaddress.ip_network(network) for network in networks)


@dataclass(frozen=True)
class Policy:
    """Everything the sandbox enforces. A layer takes a Policy and nothing else."""

    workspace: str
    read_only: tuple[str, ...] = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc")
    allowed_hosts: frozenset[str] = frozenset()
    denied_networks: tuple[Network, ...] = parse_networks(LOOPBACK_AND_LINK_LOCAL)
    memory_bytes: int = 256 * 2**20
    cpus: float = 1.0
    max_pids: int = 64

    @classmethod
    def from_json(cls, path: str) -> Policy:
        with open(path) as f:
            raw = json.load(f)
        unknown = set(raw) - {field.name for field in fields(cls)}
        if unknown:
            raise ValueError(f"{path}: unknown policy keys {sorted(unknown)}")
        policy = cls(workspace=os.path.realpath(raw.pop("workspace")))
        if "read_only" in raw:
            raw["read_only"] = tuple(raw["read_only"])
        if "allowed_hosts" in raw:
            raw["allowed_hosts"] = frozenset(
                host.lower() for host in raw["allowed_hosts"]
            )
        if "denied_networks" in raw:
            raw["denied_networks"] = parse_networks(raw["denied_networks"])
        return replace(policy, **raw)
