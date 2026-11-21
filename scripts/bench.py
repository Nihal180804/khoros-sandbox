#!/usr/bin/env python3
"""Khoros Sandbox - benchmark harness.

Measures per-execution startup latency for Khoros and, on the same machine and
workload, for whatever of bubblewrap / Docker / nsjail / isolate is installed.
The claim Khoros makes is architectural -- no daemon round-trip, no image-layer
setup, no network plumbing per run -- and this is where that claim is either
confirmed or contradicted with reproducible numbers.

What it reports, per the README's requirements:
  * p50 / p95 / p99 / mean over N runs (default 1000), not a single sample
  * kernel version, CPU model, and whether the run was warm (a warmup batch is
    discarded first, so these are warm-cache numbers; say so when quoting them)
  * for Khoros, in-engine wall_time_ms (from the runner's own JSON) reported
    separately from end-to-end latency, which includes the sudo exec
  * the same trivial workload across every engine present

It needs nothing it cannot degrade around: an engine whose binary is missing,
or whose one-shot smoke run fails, is skipped with a reason rather than
aborting the whole benchmark. The Khoros path needs passwordless sudo for the
runner (the same NOPASSWD entry the server uses).

Usage:
    python3 scripts/bench.py [--runs 1000] [--warmup 50]
                             [--engines khoros,bwrap,docker] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

ENGINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(ENGINE_DIR, "sandbox_runner")

# The workload is deliberately trivial: exit immediately. That isolates the
# sandbox's own per-run overhead from anything the program does.
INNER_CMD = ["/bin/true"]
DOCKER_IMAGE = "alpine:3.20"


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


# Each builder returns the argv to launch the workload once, or None if that
# engine is not usable here.
def khoros_cmd() -> Optional[List[str]]:
    if not os.path.isfile(RUNNER):
        return None
    return ["sudo", "-n", RUNNER, "--timeout", "10", "--cgroup", "bench", *INNER_CMD]


def bwrap_cmd() -> Optional[List[str]]:
    if not _have("bwrap"):
        return None
    return ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--unshare-all", "--die-with-parent", "--", *INNER_CMD]


def docker_cmd() -> Optional[List[str]]:
    if not _have("docker"):
        return None
    return ["docker", "run", "--rm", "--network", "none", DOCKER_IMAGE, "true"]


def nsjail_cmd() -> Optional[List[str]]:
    if not _have("nsjail"):
        return None
    return ["nsjail", "--really_quiet", "--disable_proc", "-Mo",
            "--chroot", "/", "--", *INNER_CMD]


def isolate_cmd() -> Optional[List[str]]:
    if not _have("isolate"):
        return None
    # isolate needs an initialised box; this is a best-effort single-box run.
    return ["isolate", "--run", "--", "/bin/true"]


BUILDERS: Dict[str, Tuple[Callable[[], Optional[List[str]]], str]] = {
    "khoros": (khoros_cmd, "this engine (needs passwordless sudo for the runner)"),
    "bwrap":  (bwrap_cmd,  "bubblewrap, same namespaces+seccomp class"),
    "docker": (docker_cmd, "daemon + image layers; warm-image, not cold-comparable"),
    "nsjail": (nsjail_cmd, "nsjail, same class"),
    "isolate": (isolate_cmd, "ioi/isolate judge sandbox"),
}


def percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def time_once(cmd: List[str]) -> Tuple[Optional[float], Optional[float]]:
    """Run cmd once. Returns (end_to_end_ms, in_engine_ms_or_None)."""
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    e2e_ms = (time.perf_counter() - t0) * 1000.0
    if proc.returncode != 0:
        return None, None
    in_engine = None
    # Khoros prints JSON telemetry carrying its own measured wall time.
    try:
        in_engine = float(json.loads(proc.stdout).get("wall_time_ms"))
    except Exception:
        pass
    return e2e_ms, in_engine


def smoke(cmd: List[str]) -> Optional[str]:
    """Return None if a single run succeeds, else a short failure reason."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"
    if proc.returncode != 0:
        return f"exit {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:160]}"
    return None


def summarize(name: str, e2e: List[float], engine: List[float]) -> Dict[str, object]:
    e2e_sorted = sorted(e2e)
    row: Dict[str, object] = {
        "engine": name,
        "samples": len(e2e),
        "e2e_ms": {
            "p50": round(percentile(e2e_sorted, 50), 3),
            "p95": round(percentile(e2e_sorted, 95), 3),
            "p99": round(percentile(e2e_sorted, 99), 3),
            "mean": round(statistics.fmean(e2e), 3) if e2e else float("nan"),
        },
    }
    if engine:
        eng_sorted = sorted(engine)
        row["in_engine_ms"] = {
            "p50": round(percentile(eng_sorted, 50), 3),
            "p95": round(percentile(eng_sorted, 95), 3),
            "p99": round(percentile(eng_sorted, 99), 3),
            "mean": round(statistics.fmean(engine), 3),
        }
    return row


def cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=1000, help="timed runs per engine")
    ap.add_argument("--warmup", type=int, default=50, help="discarded warmup runs")
    ap.add_argument("--engines", default=",".join(BUILDERS),
                    help="comma-separated subset to run")
    ap.add_argument("--json", default=None, help="write full results to this file")
    args = ap.parse_args()

    requested = [e.strip() for e in args.engines.split(",") if e.strip()]
    unknown = [e for e in requested if e not in BUILDERS]
    if unknown:
        print(f"unknown engine(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    env = {
        "kernel": platform.release(),
        "cpu": cpu_model(),
        "python": platform.python_version(),
        "runs": args.runs,
        "warmup": args.warmup,
        "cache": "warm (a warmup batch is discarded before timing)",
        "workload": " ".join(INNER_CMD) + " (process spin-up only)",
    }

    print("=== Khoros benchmark harness ===")
    for k, v in env.items():
        print(f"  {k:9}: {v}")
    print()

    results: List[Dict[str, object]] = []
    for name in requested:
        builder, note = BUILDERS[name]
        cmd = builder()
        if cmd is None:
            print(f"[skip] {name:8} - not installed")
            continue
        reason = smoke(cmd)
        if reason is not None:
            print(f"[skip] {name:8} - smoke run failed: {reason}")
            continue

        print(f"[run ] {name:8} - {note}")
        for _ in range(args.warmup):
            time_once(cmd)

        e2e: List[float] = []
        engine: List[float] = []
        for _ in range(args.runs):
            a, b = time_once(cmd)
            if a is not None:
                e2e.append(a)
            if b is not None:
                engine.append(b)
        if e2e:
            results.append(summarize(name, e2e, engine))

    print()
    hdr = f"{'engine':10} {'n':>6} {'p50':>9} {'p95':>9} {'p99':>9} {'mean':>9}"
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        e = r["e2e_ms"]  # type: ignore[index]
        print(f"{r['engine']:10} {r['samples']:>6} "
              f"{e['p50']:>9} {e['p95']:>9} {e['p99']:>9} {e['mean']:>9}  (end-to-end ms)")
        if "in_engine_ms" in r:
            g = r["in_engine_ms"]  # type: ignore[index]
            print(f"{'':10} {'':>6} "
                  f"{g['p50']:>9} {g['p95']:>9} {g['p99']:>9} {g['mean']:>9}  (in-engine ms)")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"environment": env, "results": results}, f, indent=2)
        print(f"\nwrote {args.json}")

    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
