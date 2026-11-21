# Design: warm worker pool

**Status:** design only. Not implemented. Unlike the other roadmap items this one
is in genuine tension with the project's stated design, so the first question is
whether to build it at all.

## The tension

Khoros's pitch is that it has **no daemon**: each run is a fresh `fork` from the
`sudo`-invoked runner, assembling namespaces, cgroup, `pivot_root` and seccomp
from scratch, then `execve`. The selling point versus Docker is precisely the
absence of a persistent service and per-run image/network setup.

A warm worker pool reintroduces a persistent privileged process. That is not
automatically wrong — the win is amortising the jail-construction cost across
runs — but it should be adopted only if the benchmark harness (`scripts/bench.py`,
`make bench`) shows jail construction is actually a material fraction of per-run
latency on the target workload. Measure first. If cold `fork`+setup is already
sub-millisecond-dominant on the eval loop, a pool adds complexity and a long-lived
root process for little gain.

## Why "pre-jailed workers" cannot be literal

The intuitive design — keep N fully-jailed processes parked, blocked, waiting for
work — does not work. A jailed leaf has already `execve`'d the target and sealed a
seccomp allowlist and dropped privileges; you cannot inject new code into it, and
it cannot `execve` a different program with new limits. Once sealed, a worker is
single-use.

So "warm" has to mean warming the part *before* the seal.

## Zygote model (the workable design)

A privileged supervisor (the warm daemon) keeps the expensive, reusable
scaffolding hot and forks a fresh leaf per request from a template:

- **Supervisor** — one long-lived root process (replaces per-request `sudo exec`
  of the runner). Holds:
  - pre-created, pre-delegated cgroup parent and a pool of pre-made child cgroups
    (mkdir + controller writes done ahead of time; only the final limit values
    are written per run);
  - a pre-resolved, ownership-checked rootfs fd;
  - the compiled seccomp program cached in memory (one `seccomp_init` +
    `seccomp_export_bpf`, reused as a raw BPF `prog` per run via
    `seccomp(SECCOMP_SET_MODE_FILTER)` — skips rebuilding the filter each time);
  - a warm namespace template is the hard part: namespaces are per-process and
    cannot be "shared out" without the processes joining them, so the realistic
    saving is the cgroup/seccomp/rootfs work, not `unshare` itself.
- **Per request** — supervisor `fork`s, the child does the (still necessary)
  `unshare` + `pivot_root` + privilege drop, loads the **cached** BPF program,
  and `execve`s. The gateway talks to the supervisor over a unix socket instead
  of `sudo`-exec'ing the runner.

Net: you save cgroup creation + controller delegation, rootfs resolution +
ownership stat, and seccomp compilation. You do **not** save `unshare`,
`pivot_root`, the mounts, or the privilege drop — those are per-process by
construction.

## What it costs

- A root-owned daemon with a request socket is now part of the attack surface and
  the thing that must not be compromised; today a crashed run takes nothing with
  it. The socket needs the same auth/authorization discipline the HTTP gateway
  has, plus careful message validation.
- Lifecycle: supervised restart, cgroup/zombie reaping across the pool, back
  pressure when all child cgroups are in use (the uid pool already models this).
- It supersedes the `sudo` NOPASSWD model; that simplification (and its footgun)
  goes away, replaced by a service unit running as root with a dropped-privilege
  socket.

## Recommended path

1. Land `make bench` (done) and measure cold per-run setup cost on the real
   workload, in-engine vs end-to-end.
2. Only if setup is a material fraction, prototype the zygote supervisor behind a
   flag, reusing the cached seccomp BPF and pre-made cgroups — the two clearly
   reusable pieces — and benchmark the warm path against the cold one with the
   same harness.
3. Keep the daemonless `sudo` runner as the default and the thing the escape
   suite targets; the pool is an optimisation, not the security boundary.
