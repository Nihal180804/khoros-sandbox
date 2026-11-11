# Khoros Sandbox

**A low-latency Linux sandbox for executing untrusted code, built on kernel isolation primitives rather than a container runtime.**

C++17 execution engine with a FastAPI gateway. Intended for AI agent evaluation loops and competitive-programming judges, where per-execution startup cost compounds across many short runs.

![C++17](https://img.shields.io/badge/Language-C%2B%2B17-00599C?logo=c%2B%2B&logoColor=white)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![cgroups v2](https://img.shields.io/badge/Isolation-cgroups%20v2-E95420?logo=linux&logoColor=white)
![Seccomp allowlist](https://img.shields.io/badge/Seccomp-default--deny-4CAF50?logo=shield&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

---

## Contents

- [What it does](#what-it-does)
- [Threat model](#threat-model)
- [Security architecture](#security-architecture)
- [Execution lifecycle](#execution-lifecycle)
- [Verdicts and telemetry](#verdicts-and-telemetry)
- [HTTP API](#http-api)
- [CLI reference](#cli-reference)
- [Getting started](#getting-started)
- [Testing](#testing)
- [Performance](#performance)
- [How this compares](#how-this-compares)
- [Roadmap](#roadmap)
- [License](#license)

---

## What it does

Khoros runs a program you do not trust and returns its output, exit status, peak memory and a verdict, having bounded what it could read, write, reach and consume.

It does this without a container runtime. There is no daemon, no image layer, no virtual ethernet pair and no VM boot. The engine is a single binary that assembles the isolation directly out of namespaces, cgroups v2, `pivot_root` and seccomp-BPF, then execs the target.

Two languages are wired up today: Python 3, and C++17 via a two-stage compile-then-execute pipeline where both stages run inside separate jails.

---

## Threat model

Being explicit about this matters more than any benchmark.

**Assumed attacker.** Arbitrary, hostile code of their choosing, in a supported language, with full knowledge of this design. They may attempt kernel-surface attacks, resource exhaustion, and escape via any syscall reachable from the jail.

**What Khoros is built to prevent:**

| Goal | Mechanism |
|---|---|
| Reading or writing the host filesystem | `pivot_root` into a read-only rootfs; unprivileged uid; only the per-run workspace and a tmpfs `/tmp` are writable |
| Gaining privilege on the host | Runs as an unprivileged uid with an empty capability bounding set, `NO_NEW_PRIVS`, and locked `SECBIT_NOROOT` |
| Reaching the network | `CLONE_NEWNET` with no interfaces, plus no socket syscall in the allowlist |
| Attacking the kernel through exotic syscalls | Default-deny seccomp allowlist |
| Exhausting host memory, pids or CPU | cgroups v2 `memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max`, all fail-closed |
| Outliving its budget | `SIGALRM` watchdog plus atomic `cgroup.kill`; `RLIMIT_CPU` as a backstop |
| Affecting a later run | Read-only rootfs; per-run workspace deleted by the privileged runner |
| Exhausting host memory via output | Both streams drained concurrently and capped at 1 MiB each |

**Explicit non-goals.** Khoros does *not* defend against kernel 0-days reachable through the allowed syscall set — a container-grade sandbox never does, which is why gVisor and Firecracker exist. It does not provide a user namespace (see Roadmap), per-run uid isolation, side-channel resistance, or any guarantee about timing attacks between concurrent runs. It is not audited, and it has not been run in production.

If you need a sandbox with a track record, use [nsjail](https://github.com/google/nsjail), [bubblewrap](https://github.com/containers/bubblewrap) or [isolate](https://github.com/ioi/isolate). Khoros was built to understand how these things actually work, and it is measured against them rather than against a strawman.

---

## Security architecture

Isolation is applied in a fixed order, and every privileged step completes before any untrusted instruction executes.

**Parent process (root)**

Validates every argument, including client-supplied limits. Resolves the rootfs from `/proc/self/exe` — not the working directory — and refuses it unless it is root-owned and not group- or world-writable. Creates the cgroup, delegates the `memory`, `pids` and `cpu` controllers through the parent's `cgroup.subtree_control`, and applies the limits. **Any failure here aborts before the child is released.** Pre-opens `cgroup.kill` so the signal handler allocates nothing, then arms the watchdog.

**Middle child**

Blocks on a sync pipe until the parent confirms it is inside the cgroup — a short read or EOF aborts rather than running unconfined. Then `unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP)` and forks the leaf, which becomes PID 1 of the new pid namespace.

**Jailed leaf**

| Layer | Mechanism | What it stops |
|---|---|---|
| Mount isolation | `MS_REC\|MS_PRIVATE`, bind + `MS_REMOUNT\|MS_RDONLY\|MS_NOSUID\|MS_NODEV` | Host mount tampering; a run modifying the rootfs for later runs |
| Root pivot | `pivot_root` into a pre-created `.old_root`, then `MNT_DETACH` | Host filesystem access. The put_old directory is created once at bootstrap, not per run, which removes a race between concurrent executions |
| Writable surface | RW bind of the run's workspace, `nosuid,nodev`; tmpfs `/tmp`; read-only minimal `/dev` | Persistence and host disk exhaustion |
| Process view | `/proc` mounted `nosuid,nodev,noexec` inside the pid namespace | Host process recon and signalling |
| Privilege | `NO_NEW_PRIVS`, `SECBIT_NOROOT` locked, ambient caps cleared, full bounding-set drop, `setresgid`/`setresuid` | Everything that root in the initial user namespace unlocks: writing `core_pattern`, `mknod` on a host block device, `finit_module`, remounting cgroups |
| Verification | Asserts uid/gid took effect and that `setuid(0)` now fails | A silently failed privilege drop |
| Resource limits | `RLIMIT_CORE=0`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CPU` | Core dumps, disk fill, fd exhaustion, CPU overrun |
| Syscalls | seccomp-BPF allowlist, default `EPERM` | `io_uring`, `bpf`, `keyctl`, `userfaultfd`, `perf_event_open`, `ptrace`, `mount`, the newer `fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree` mount API, module loading, and anything a future kernel adds |

Two details in the syscall filter are worth calling out. `clone` is argument-filtered to refuse namespace flags while still permitting threads and ordinary forks. `clone3` cannot be filtered — its flags live behind a struct pointer — so it returns `ENOSYS` rather than `EPERM`, which makes glibc's `pthread_create` fall back to `clone` instead of failing outright. musl uses `clone` directly, so Alpine is unaffected either way.

A denylist cannot achieve this. The three-syscall denylist this engine started with left `io_uring`, `bpf`, module loading and the entire new mount API reachable.

---

## Execution lifecycle

```
Client / LLM agent
   │  POST /execute
   ▼
FastAPI gateway (api/server.py)
   │  clamps limits, bounds concurrency, writes the source into a 0700 scratch dir
   ▼
sudo sandbox_runner  ── parent, root ──────────────────────────────────┐
   │  resolve rootfs via /proc/self/exe + ownership checks             │
   │  create cgroup, delegate controllers, apply mem/pids/cpu          │
   │  chown workspace to the sandbox uid                               │
   │  pre-open cgroup.kill, fork, release child through the sync pipe  │
   │  arm SIGALRM                                                      │
   │                                                                   │
   ├─ middle child ── unshare(NS|PID|NET|IPC|UTS|CGROUP), fork leaf     │
   │                                                                   │
   │   └─ leaf (PID 1 of its namespace)                                │
   │        read-only rootfs bind → RW workspace bind → pivot_root     │
   │        mount /proc, minimal /dev, tmpfs /tmp                      │
   │        NO_NEW_PRIVS → securebits → drop bounding set → setuid     │
   │        rlimits → seccomp allowlist → execve                       │
   │                                                                   │
   │  poll() both pipes concurrently, capped at 1 MiB each             │
   │  on timeout: write cgroup.kill (async-signal-safe)                │
   │  read memory.peak and memory.events, tear down the cgroup         │
   │  delete the workspace contents, return it to the caller           │
   └─ emit JSON telemetry ─────────────────────────────────────────────┘
```

---

## Verdicts and telemetry

```json
{
  "verdict": "OK",
  "exit_code": 0,
  "wall_time_ms": 34,
  "peak_memory_bytes": 7168000,
  "oom_killed": false,
  "timed_out": false,
  "stdout_truncated": false,
  "stderr_truncated": false,
  "stdout": "Hello from the sandbox\n",
  "stderr": ""
}
```

| Verdict | Meaning |
|---|---|
| `OK` | Exited 0 within every budget |
| `TIME_LIMIT_EXCEEDED` | The wall-clock watchdog fired |
| `MEMORY_LIMIT_EXCEEDED` | The cgroup OOM-killed the task, per `memory.events` |
| `COMPILATION_ERROR` | The compile stage returned non-zero; `stderr` holds the diagnostics |
| `NON_ZERO_EXIT` | The program ran and exited non-zero |
| `SIGNAL_TERMINATED` | Killed by an unexpected signal (`SIGSEGV`, `SIGFPE`, `SIGABRT`) |
| `KILLED` | `SIGKILL` with neither a timeout nor an OOM recorded |
| `SANDBOX_ERROR` | The engine itself failed; `stderr` carries the reason |

Time and memory are reported separately because they are distinguished at the source: `memory.events`' `oom_kill` counter decides. The older combined `TIME_OR_MEMORY_LIMIT_EXCEEDED` verdict is gone.

`stdout` and `stderr` are always valid UTF-8 JSON. Well-formed UTF-8 passes through untouched; invalid bytes become `U+FFFD`, so a program emitting binary cannot break the client's JSON parser.

---

## HTTP API

### `POST /execute`

```json
{
  "language": "python | cpp",
  "code": "string (<= 256 KiB)",
  "stdin": "string (optional, <= 256 KiB)",
  "timeout_sec": 2,
  "mem_mb": 64
}
```

Limits are clamped by the gateway and validated again by the runner. Neither layer trusts the other.

Set `KHOROS_API_KEY` to require an `X-API-Key` header. The server binds `127.0.0.1` by default; expose it only behind an authenticating proxy, and set the key if you do.

Concurrency is bounded by `KHOROS_MAX_CONCURRENT` (default 8). Requests beyond that wait up to 30 s, then receive `503`.

```bash
curl -X POST http://127.0.0.1:8000/execute \
  -H 'Content-Type: application/json' \
  -d '{"language":"python","code":"print(sum(x*x for x in range(10)))"}'
```

### `GET /healthz`

Reports whether the runner binary and rootfs are present, the concurrency ceiling, and whether auth is enabled.

---

## CLI reference

The engine runs standalone, without the HTTP layer.

```bash
sudo ./sandbox_runner [options] /absolute/path/to/cmd [args...]
```

| Flag | Default | Description |
|---|---|---|
| `--timeout <sec>` | `2` | Wall-clock limit, 1–60 |
| `--mem <mb>` | `64` | Memory ceiling, 8–2048; swap disabled |
| `--pids <n>` | `16` | Max tasks in the cgroup, 1–256 |
| `--cpus <f>` | `1.0` | CPU cores via `cpu.max`, (0, 8] |
| `--tmp <mb>` | `64` | Size of the in-jail `/tmp` tmpfs |
| `--cgroup <id>` | `exec_default` | Slice name, `[A-Za-z0-9_-]{1,64}` |
| `--workdir <rel>` | — | Writable directory relative to the rootfs |
| `--cleanup` | off | Delete the workdir contents afterwards. Pass only on the final stage of a pipeline |
| `--uid <n>` / `--gid <n>` | `65534` | Unprivileged identity for the jail |
| `--seccomp <mode>` | `enforce` | `enforce`, `log` (discover missing syscalls), or `off` |

The command must be an absolute path; nothing is resolved through `PATH` inside the jail, and the environment is replaced with a minimal fixed set.

```bash
sudo ./sandbox_runner --timeout 3 --mem 128 --cgroup run01 \
    --uid 958 --gid 958 /usr/bin/python3 -c "print('hello')"
```

---

## Getting started

**Requirements.** Linux with cgroups v2 at `/sys/fs/cgroup` (kernel 5.19+ for `memory.peak`), `libseccomp`, a C++17 compiler, Python 3.10+.

```bash
# Arch
sudo pacman -S --needed base-devel libseccomp python curl
# Debian / Ubuntu
sudo apt install -y build-essential libseccomp-dev python3 python3-venv curl
```

Confirm the root cgroup delegates what the engine needs. If `memory` is absent here, no limit below it can be enforced:

```bash
cat /sys/fs/cgroup/cgroup.subtree_control   # expect: ... cpu ... memory ... pids ...
```

```bash
python -m venv .venv && source .venv/bin/activate
pip install fastapi uvicorn

make bootstrap        # verified Alpine rootfs, khoros-sandbox user, mount points
make build
make install-runner   # root-owns the binary, creates the cgroup parent
```

`make bootstrap` prints the sandbox uid and gid:

```bash
export KHOROS_SANDBOX_UID=$(id -u khoros-sandbox)
export KHOROS_SANDBOX_GID=$(id -g khoros-sandbox)
```

Grant sudo for the runner alone:

```bash
echo "$USER ALL=(ALL) NOPASSWD: $(pwd)/sandbox_runner" | sudo tee /etc/sudoers.d/khoros_runner
sudo chmod 0440 /etc/sudoers.d/khoros_runner
```

> **Note.** A `NOPASSWD` entry pointing into a directory you can write to is still a local privilege-escalation path: write permission on the directory lets you replace the root-owned binary. For anything beyond local development, install the binary and its rootfs together under a root-owned prefix such as `/usr/local/lib/khoros/`. They must move as a pair, because the runner derives its rootfs from `/proc/self/exe`.

```bash
make server     # 127.0.0.1:8000
```

---

## Testing

```bash
make test           # 13 functional smoke tests
make escape-tests   # 23 adversarial cases
```

`scripts/escape_tests.py` is the substance of the security claims above. Each case names the threat it covers, so a failure says what regressed rather than only that something did. Coverage:

- **Privilege** — not uid 0; `CapEff` is zero; `setuid(0)` fails
- **Host takeover** — `core_pattern` not writable; `mknod`, `mount`, the new mount API, `finit_module`, `io_uring`, `bpf`, `unshare` and `ptrace` all refused
- **Filesystem** — rootfs is read-only; no writes outside the workspace and `/tmp`; `/proc/1/root` is the jail root, not the host
- **Namespaces** — pid namespace isolated; sockets refused
- **Resources** — fork bomb contained; memory ceiling enforced; watchdog enforced; a stderr flood does not deadlock; stdout is capped; the client cannot disable the watchdog

When a legitimate program dies with `Operation not permitted`, it is usually a syscall the allowlist is missing. Find it:

```bash
sudo ./sandbox_runner --seccomp log --cgroup dbg /usr/bin/python3 -c 'print(1)'
sudo dmesg | grep -i seccomp | tail -20
```

---

## Performance

**No benchmark numbers are published here yet, deliberately.** The engine's measured `wall_time_ms` starts inside the runner, so it excludes the `sudo` exec, the HTTP handling and the scratch-file write — reporting it as end-to-end latency would overstate the result. Earlier versions of this README carried figures produced without a reproducible harness; they have been removed rather than restated.

`make bench` is the open work item. It needs to:

- report p50/p95/p99 over at least 1,000 runs, not a single sample
- record kernel version, CPU model and whether the page cache was warm
- separate in-engine latency from end-to-end API latency
- run the same workloads against nsjail, bubblewrap, isolate and Docker on the same machine
- publish the script so the numbers can be reproduced or contradicted

Until that exists, the honest claim is architectural: Khoros skips the daemon round-trip, image-layer setup and network plumbing that a container runtime performs per execution. Whether that converts into a latency win worth having is exactly what the harness is for.

---

## How this compares

| | Docker / Podman | Firecracker | gVisor | nsjail / bubblewrap / isolate | Khoros |
|---|---|---|---|---|---|
| Isolation primitive | namespaces + cgroups | hardware virtualization | syscall interception | namespaces + cgroups + seccomp | namespaces + cgroups + seccomp |
| Daemon | yes | VMM per VM | no | no | no |
| Per-run image setup | overlay layers | VM boot | sandbox boot | none | none |
| Kernel-0-day resistance | low | high | high | low | low |
| Maturity | production | production | production | production, widely deployed | a learning project |

Khoros sits in the same category as nsjail and isolate — the same primitives, less maturity. It is not a Docker replacement, and "container-less" describes the absence of a runtime and image format, not the absence of containerization primitives; `runc` uses the same kernel features.

---

## Roadmap

- [x] Container-less isolation via namespaces, cgroups v2 and `pivot_root`
- [x] Unprivileged execution with a full capability drop
- [x] Default-deny seccomp allowlist
- [x] Read-only rootfs with a per-run writable workspace
- [x] Fail-closed cgroup limits with controller delegation
- [x] Separate time and memory verdicts from `memory.events`
- [x] Adversarial test suite
- [ ] **User namespace** — the remaining defence-in-depth gap. A regained uid 0 is currently uid 0 in the initial user namespace
- [ ] **Per-run uid** from a pool, so concurrent runs cannot reach each other's workspace
- [ ] **Reproducible benchmark harness** against nsjail, bubblewrap, isolate and Docker
- [ ] **Warm worker pool** — pre-forked, pre-jailed workers
- [ ] **OverlayFS workspace** — copy-on-write instead of a bind-mounted directory
- [ ] **More runtimes** — Rust, Go, Node.js
- [ ] **Prometheus exporter** — verdict counts, latency histograms, peak-memory distribution

---

## License

MIT. See [LICENSE](LICENSE).
