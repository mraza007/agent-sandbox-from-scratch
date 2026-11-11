#!/usr/bin/env python3
"""Run every attack at every level and check each result against expected.py.

    run_matrix.py --out DIR [--repeat 2] [--timing-runs 30]

Run as the unprivileged user, after lab.py setup and cgroup_setup.py. Writes
results.json and results.md to DIR. Exits non-zero if any cell is wrong, if
two runs of the matrix disagree, or if a sandbox left state behind.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from typing import Any, Callable

import lab
import landlock
import seccomp
from expected import ABLATIONS, EXPECTED, LEVELS, Column
from report import markdown
from sandbox import Layer
from world import SANDBOX, SCRATCH, WORKSPACE, World, write

# What the attacker must be holding when an attack says "allowed".
LOOT: dict[str, Callable[[World], str]] = {
    "read_secret": lambda world: world.secret,
    "read_secret_dotdot": lambda world: world.secret,
    "read_host_tmp": lambda world: world.host_tmp_secret,
    "inherited_fd": lambda world: world.secret,
    "fd_from_host_service": lambda world: world.secret,
    "list_host_processes": lambda world: world.victim_pid(),
    "sysv_shm": lambda world: world.shm_secret,
    "abstract_socket": lambda world: world.host_service.token,
    "direct_tcp": lambda world: world.token(lab.DENIED),
    "metadata_direct": lambda world: world.token(lab.METADATA),
    "metadata_via_proxy": lambda world: world.token(lab.METADATA),
    "ctl_proxy_allowed": lambda world: world.token(lab.ALLOWED),
    "gap_env_secret": lambda world: world.env_secret,
    "gap_workspace_secret": lambda world: world.workspace_secret,
}

# Did the effect happen, seen from outside the sandbox? Must agree with "allowed".
WITNESS: dict[str, Callable[[World], bool]] = {
    "write_outside": lambda world: world.holds_marker(world.bashrc_path),
    "write_read_only_path": lambda world: world.holds_marker(world.planted_path),
    "write_read_only_submount": lambda world: world.holds_marker(
        world.planted_in_submount
    ),
    "kill_host_process": lambda world: world.victim_died(),
    "abstract_socket": lambda world: world.host_service.connections > 0,
    "direct_tcp": lambda world: world.reached(lab.DENIED, "direct_tcp"),
    "proxy_denied_host": lambda world: world.reached(lab.DENIED, "proxy_denied_host"),
    "metadata_direct": lambda world: world.reached(lab.METADATA, "metadata_direct"),
    "metadata_via_proxy": lambda world: world.reached(
        lab.METADATA, "metadata_via_proxy"
    ),
    "ctl_proxy_allowed": lambda world: world.reached(lab.ALLOWED, "ctl_proxy_allowed"),
    "ctl_workspace_write": lambda world: world.holds_marker(world.control_path),
    "gap_git_hook": lambda world: world.holds_marker(world.git_hook_path),
}

# The host the proxy must have logged exactly one decision about.
PROXY_TARGET = {
    "proxy_denied_host": lab.DENIED.name,
    "metadata_via_proxy": lab.METADATA.name,
    "ctl_proxy_allowed": lab.ALLOWED.name,
}

# The cgroup counter that must have moved when a limit is what stopped the attack.
LIMIT_COUNTER = {
    "fork_bomb": "pids.events.max",
    "memory_hog": "memory.events.oom_kill",
    "cpu_hog": "cpu.stat.nr_throttled",
}


def last_json_line(text: str) -> dict | None:
    for line in reversed(text.splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    return None


def run_cell(world: World, column: Column, attack: str) -> dict:
    """Run one attack under one column and list every way the result is wrong."""
    done = world.run(column, "attacks.py", attack)
    result = last_json_line(done.stdout) or {
        "outcome": "error",
        "error": f"no result line, exit code {done.returncode}",
        "detail": done.stderr.strip()[-300:],
    }
    outcome, error, detail = result["outcome"], result["error"], str(result["detail"])
    expected = column.expect(attack)
    problems = []

    if "Traceback" in done.stderr:
        problems.append("traceback on stderr: " + done.stderr.strip()[-300:])
    if (outcome, error) != (expected.outcome, expected.error):
        problems.append(f"expected {expected.outcome} {expected.error or ''}".strip())
    if expected.detail is not None and detail != expected.detail:
        problems.append(f"expected detail {expected.detail!r}")
    if outcome == "allowed" and attack in LOOT and detail != LOOT[attack](world):
        problems.append("says allowed but does not hold the planted value")
    if attack in WITNESS and WITNESS[attack](world) != (outcome == "allowed"):
        problems.append("the effect seen from outside disagrees with the outcome")
    if attack in PROXY_TARGET and outcome != "n/a":
        decisions = world.events("egress")
        said = [(decision["host"], decision["allow"]) for decision in decisions]
        if said != [(PROXY_TARGET[attack], outcome == "allowed")]:
            problems.append(f"proxy log does not match: {decisions}")
        elif outcome == "blocked" and error != f"403 {decisions[0]['reason']}":
            problems.append(f"proxy logged reason {decisions[0]['reason']!r}")
    if attack in LIMIT_COUNTER and outcome == "blocked":
        counters = world.events("limits")
        if not counters or counters[0][LIMIT_COUNTER[attack]] < 1:
            problems.append(f"{LIMIT_COUNTER[attack]} did not move: {counters}")

    return {
        "column": column.name,
        "attack": attack,
        "outcome": outcome,
        "error": error,
        "detail": detail,
        "problems": problems,
    }


def run_matrix(world: World) -> list[dict]:
    cells = []
    for column in LEVELS + ABLATIONS:
        failed = 0
        for attack in EXPECTED:
            cell = run_cell(world, column, attack)
            cells.append(cell)
            if cell["problems"]:
                failed += 1
                print(f"FAIL {column.name} {attack}: {cell}", flush=True)
        print(f"{column.name}: {len(EXPECTED) - failed}/{len(EXPECTED)}", flush=True)
    return cells


def syscall_coverage(world: World) -> list[dict]:
    """Compare each denied syscall's errno one level below the filter and at it."""

    def errnos(level: int) -> dict[str, str]:
        done = world.run(LEVELS[level], "syscall_probe.py")
        lines = [json.loads(line) for line in done.stdout.splitlines()]
        return {line["syscall"]: line["errno"] for line in lines}

    below = errnos(Layer.SYSCALL_FILTER - 1)
    at = errnos(Layer.SYSCALL_FILTER)
    rows = []
    for name in (*seccomp.DENIED, "clone3"):
        wanted = "ENOSYS" if name == "clone3" else "EPERM"
        without, with_filter = below.get(name, "missing"), at.get(name, "missing")
        if with_filter != wanted:
            verdict = "FAIL"
        elif without == wanted:
            verdict = "refused, but the kernel says the same without the filter"
        else:
            verdict = "the filter refused it"
        rows.append(
            {
                "syscall": name,
                "without": without,
                "with_filter": with_filter,
                "verdict": verdict,
            }
        )
    return rows


def measure_startup(runs: int) -> dict:
    """Time a whole sandbox.py process that runs /bin/true, at each level."""
    policy = os.path.join(SCRATCH, "policy-timing.json")
    write(policy, json.dumps({"workspace": WORKSPACE}))  # the default limits

    def sandbox(level: int, *command: str) -> list[str]:
        prefix = [sys.executable, SANDBOX, "--level", str(level), "--policy", policy]
        return [*prefix, "--", *command]

    def run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, cwd=WORKSPACE, capture_output=True, text=True)

    for level in range(len(LEVELS)):
        said = run(sandbox(level, "sh", "-c", "echo ran"))
        if said.stdout.strip() != "ran":
            raise SystemExit(f"timing: L{level} did not run its command: {said.stderr}")

    targets = {"exec only": ["/bin/true"]}
    targets |= {
        f"L{level}": sandbox(level, "/bin/true") for level in range(len(LEVELS))
    }
    samples: dict[str, list[float]] = {name: [] for name in targets}
    failures = 0
    warm_up = 3
    load_before = os.getloadavg()[0]
    for round_number in range(warm_up + runs):
        # One run of each target per round, so drift and noise hit every level alike.
        for name, command in targets.items():
            started = time.perf_counter()
            code = run(command).returncode
            elapsed_ms = (time.perf_counter() - started) * 1000
            failures += code != 0
            if round_number >= warm_up:
                samples[name].append(elapsed_ms)

    def summary(values: list[float]) -> dict:
        p25, median, p75 = statistics.quantiles(values, n=4)
        return {
            "median_ms": round(median, 2),
            "p25_ms": round(p25, 2),
            "p75_ms": round(p75, 2),
            "min_ms": round(min(values), 2),
            "max_ms": round(max(values), 2),
        }

    return {
        "runs_per_target": runs,
        "warm_up_runs_discarded": warm_up,
        "failed_runs": failures,
        "cpus": os.cpu_count(),
        "load_average_before": load_before,
        "load_average_after": os.getloadavg()[0],
        "targets": {name: summary(values) for name, values in samples.items()},
    }


def leftover_state() -> list[str]:
    """Stage directories and cgroups that a sandbox should have removed."""
    cgroups = glob.glob("/sys/fs/cgroup/**/sandbox-*", recursive=True)
    return glob.glob("/tmp/sandbox-*") + cgroups


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--timing-runs", type=int, default=30)
    args = parser.parse_args()

    world = World()
    world.build()
    runs = [run_matrix(world) for _ in range(args.repeat)]

    def verdicts(cells: list[dict]) -> list[tuple]:
        return [
            (c["column"], c["attack"], c["outcome"], c["error"], bool(c["problems"]))
            for c in cells
        ]

    report: dict[str, Any] = {
        "environment": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "landlock_abi": landlock.abi_version(),
        },
        "matrix_runs": len(runs),
        "cells_per_run": len(runs[0]),
        "failed_cells": sum(bool(c["problems"]) for cells in runs for c in cells),
        "runs_identical": all(verdicts(cells) == verdicts(runs[0]) for cells in runs),
        "leftover_sandbox_state": leftover_state(),
        "syscall_coverage": syscall_coverage(world),
        "timing": measure_startup(args.timing_runs),
        "runs": runs,
    }
    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump(report, f, indent=1)
    with open(os.path.join(args.out, "results.md"), "w") as f:
        f.write(markdown(report))

    ok = (
        report["failed_cells"] == 0
        and report["runs_identical"]
        and not report["leftover_sandbox_state"]
        and all(row["verdict"] != "FAIL" for row in report["syscall_coverage"])
        and report["timing"]["failed_runs"] == 0
    )
    print("PASS" if ok else "FAIL", f"({report['failed_cells']} cells failed)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
