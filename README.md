# Agent sandbox from scratch

A sandbox for AI agent commands, built from Linux primitives in Python with the
standard library only. Each level adds one layer, so you can watch an attack
work at one level and fail at the next.

This is the code for the post
[Building an Agent Sandbox from Scratch in Python](https://muhammadraza.me/2026/building-agent-sandbox-python/).

| Level | Layer | What it adds |
| --- | --- | --- |
| 0 | none | The command runs as you. |
| 1 | `rootless_start` | User, PID, IPC and UTS namespaces. No root. |
| 2 | `new_root` | Mount namespace, bind mounts, `pivot_root`. |
| 3 | `syscall_filter` | `no_new_privs` and a hand-built seccomp-bpf filter. |
| 4 | `path_rules` | Landlock. |
| 5 | `private_network` | Empty network namespace. Egress only through an allowlist proxy. |
| 6 | `resource_limits` | cgroup v2 memory, CPU and pids limits. |

## Run the tests

You need Docker. On a Mac, Docker runs a Linux VM, which is what this code needs.

```sh
./run-in-docker.sh
```

This builds a small image, runs every attack at every level twice, measures
start-up time, and writes `results.md` and `results.json` here. It takes about
two minutes. The container runs with `--network none`.

## Use the sandbox

On Linux, as an ordinary user:

```sh
python3 sandbox.py --level 5 -- bash
python3 sandbox.py --level 6 --policy policy.json -- python3 agent_tool.py
```

Level 6 needs one root step first. See `cgroup_setup.py`.

A policy file sets any field of `Policy` in `policy.py`:

```json
{
  "workspace": "/home/me/project",
  "allowed_hosts": ["pypi.org", "files.pythonhosted.org"],
  "memory_bytes": 536870912,
  "cpus": 1.0,
  "max_pids": 128
}
```

## Files

| File | Role |
| --- | --- |
| `policy.py` | The `Policy` dataclass. Every layer reads it. |
| `sandbox.py` | The six layers, the order they run in, and the command line. |
| `syscalls.py` | Syscall numbers and thin wrappers for calls Python does not have. |
| `seccomp.py` | The BPF filter, built instruction by instruction. |
| `landlock.py` | Landlock through its three raw syscalls. |
| `egress.py` | The host-side CONNECT proxy and the relay inside the sandbox. |
| `cgroup_setup.py` | The one step that needs root: delegate a cgroup subtree. |
| `attacks.py` | What a hostile agent tries. Runs inside the sandbox. |
| `syscall_probe.py` | Calls each denied syscall, to show the filter answers. |
| `expected.py` | The expected result of every attack at every level. |
| `lab.py` | Fake allowed, denied and metadata servers, all on loopback. |
| `world.py` | Host-side test state: secrets, victims, what the harness can see. |
| `run_matrix.py` | Runs the matrix, checks it, times start-up. |
| `report.py` | Writes `results.md`. |

## Limits

Tested on aarch64 only. The x86_64 syscall numbers match the kernel's table but
have not been run. This is teaching code. It shares the host kernel, so a kernel
bug reachable through an allowed syscall defeats every layer. `results.md` lists
attacks it does not stop.
