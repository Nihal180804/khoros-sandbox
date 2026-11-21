"""Khoros Sandbox - FastAPI gateway.

Responsibilities, in order of importance:
  * Clamp every execution limit from the request body. The runner validates
    them again; neither layer trusts the other.
  * Allocate a distinct uid/gid per concurrent run from a fixed pool, so two
    runs in flight at the same time cannot signal or inspect each other. The
    pool doubles as the concurrency bound: N identities => at most N jails.
  * Guard json.loads of the runner output, so a runner that dies before
    printing JSON yields a SANDBOX_ERROR verdict instead of a 500.
  * Require an API key when KHOROS_API_KEY is set; bind 127.0.0.1 by default.
  * Create per-run scratch dirs 0700 and hand them to the sandbox uid via the
    runner, instead of a world-writable workspace.
  * Export Prometheus metrics at /metrics.

Languages are described by a single LANGUAGES table; interpreted ones run in
one jail, compiled ones (cpp/rust/go) compile in one jail and execute the
artifact in a second. Set KHOROS_OVERLAY=1 to use the runner's copy-on-write
overlay workspace instead of a plain bind mount.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import secrets
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pydantic import BaseModel, Field

log = logging.getLogger("khoros")

ENGINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOTFS_DIR = os.path.join(ENGINE_DIR, "rootfs")
WORKSPACE_REL = "workspace"
ROOTFS_WORKSPACE = os.path.join(ROOTFS_DIR, WORKSPACE_REL)
RUNNER_PATH = os.path.join(ENGINE_DIR, "sandbox_runner")

# Hard ceilings. The runner validates these again; never trust one layer.
MAX_TIMEOUT_SEC = 30
MAX_MEM_MB = 512
MAX_CODE_BYTES = 256 * 1024
MAX_STDIN_BYTES = 256 * 1024
MAX_CONCURRENT = int(os.environ.get("KHOROS_MAX_CONCURRENT", "8"))
COMPILE_TIMEOUT_SEC = 20

API_KEY = os.environ.get("KHOROS_API_KEY")  # unset => no auth (localhost only)

# Opt-in copy-on-write workspace (runner --overlay). Default off keeps the
# bind-mount path that the escape suite validates.
OVERLAY = os.environ.get("KHOROS_OVERLAY", "0") == "1"

# --------------------------------------------------------------------------
# Per-run identity pool
#
# Each concurrent run gets its own (uid, gid) drawn from a contiguous range, so
# simultaneous runs are isolated from one another, not just from the host. The
# pool is sized to MAX_CONCURRENT and getting an identity *is* the concurrency
# gate, which also means a run can never start without one. High ids avoid
# collisions with system users; setresuid(2) does not require a passwd entry.
# --------------------------------------------------------------------------
UID_POOL_BASE = int(os.environ.get("KHOROS_UID_POOL_BASE", "100000"))
UID_POOL_SIZE = int(os.environ.get("KHOROS_UID_POOL_SIZE", str(MAX_CONCURRENT)))
if UID_POOL_BASE < 1000:
    raise RuntimeError("KHOROS_UID_POOL_BASE must be >= 1000 (0 is root)")
if UID_POOL_SIZE < 1:
    raise RuntimeError("KHOROS_UID_POOL_SIZE must be >= 1")

_identities: "queue.Queue[tuple[int, int]]" = queue.Queue()
for _n in range(UID_POOL_SIZE):
    _identities.put((UID_POOL_BASE + _n, UID_POOL_BASE + _n))

# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------
M_EXEC = Counter("khoros_executions_total", "Executions by language and verdict",
                 ["language", "verdict"])
M_WALL = Histogram("khoros_wall_time_ms", "In-engine wall time (ms), as the runner reports it",
                   buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000))
M_PEAK = Histogram("khoros_peak_memory_bytes", "Peak RSS of the run (bytes)",
                   buckets=(1e6, 5e6, 1e7, 2.5e7, 5e7, 1e8, 2.5e8, 5e8, 1e9))
M_E2E = Histogram("khoros_e2e_seconds", "End-to-end request handling time (s)",
                  buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60))
M_SLOTS = Gauge("khoros_slots_in_use", "Identities currently checked out of the pool")

# --------------------------------------------------------------------------
# Language table. {dir} is substituted with the directory the jail sees the
# source in (the overlay merged dir when OVERLAY is on, the workspace dir
# otherwise). Compiled languages reuse the two-jail compile->execute pipeline.
# --------------------------------------------------------------------------
LANGUAGES: Dict[str, Dict[str, Any]] = {
    "python": {
        "file": "solution.py",
        "run": ["/usr/bin/python3", "{dir}/solution.py"],
    },
    "node": {
        "file": "solution.js",
        "run": ["/usr/bin/node", "{dir}/solution.js"],
    },
    "cpp": {
        "file": "solution.cpp",
        "compile": ["/usr/bin/g++", "-O2", "-std=c++17", "{dir}/solution.cpp", "-o", "{dir}/solution"],
        "run": ["{dir}/solution"],
        "compile_mem": 384, "compile_pids": 32,
    },
    "rust": {
        "file": "solution.rs",
        "compile": ["/usr/bin/rustc", "-O", "{dir}/solution.rs", "-o", "{dir}/solution"],
        "run": ["{dir}/solution"],
        "compile_mem": 512, "compile_pids": 64,
    },
    "go": {
        "file": "solution.go",
        "compile": ["/usr/bin/go", "build", "-o", "{dir}/solution", "{dir}/solution.go"],
        "run": ["{dir}/solution"],
        "compile_mem": 512, "compile_pids": 64,
    },
}
_LANG_PATTERN = "^(" + "|".join(LANGUAGES) + ")$"

app = FastAPI(title="Khoros Sandbox Engine", version="2.1")


class ExecutionRequest(BaseModel):
    language: str = Field(pattern=_LANG_PATTERN)
    code: str
    stdin: Optional[str] = ""
    timeout_sec: int = Field(default=2, ge=1, le=MAX_TIMEOUT_SEC)
    mem_mb: int = Field(default=64, ge=8, le=MAX_MEM_MB)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_KEY is None:
        return
    if x_api_key is None or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def _run_stage(
    argv: List[str],
    *,
    uid: int,
    gid: int,
    run_id: str,
    workdir_rel: str,
    timeout: int,
    mem_mb: int,
    pids: int,
    cleanup: bool,
    stdin_data: str = "",
) -> Dict[str, Any]:
    """Invoke the C++ runner for one jail and parse its JSON telemetry.

    Never raises on malformed output: a runner that dies before printing JSON
    yields a SANDBOX_ERROR verdict carrying its stderr, which is far easier to
    debug than a FastAPI traceback.
    """
    cmd = [
        "sudo", "-n", RUNNER_PATH,
        "--uid", str(uid), "--gid", str(gid),
        "--timeout", str(timeout),
        "--mem", str(mem_mb),
        "--pids", str(pids),
        "--cgroup", run_id,
        "--workdir", workdir_rel,
    ]
    if OVERLAY:
        cmd.append("--overlay")
    if cleanup:
        cmd.append("--cleanup")
    cmd += argv

    try:
        proc = subprocess.run(
            cmd,
            cwd=ENGINE_DIR,
            input=stdin_data,
            capture_output=True,
            text=True,
            errors="replace",
            # Outer guard only; the real limit is the runner's own watchdog.
            timeout=MAX_TIMEOUT_SEC + 30,
        )
    except subprocess.TimeoutExpired:
        return {
            "verdict": "SANDBOX_ERROR",
            "exit_code": -1,
            "stdout": "",
            "stderr": "runner exceeded its outer timeout",
        }

    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        log.error("runner produced no JSON (rc=%s): %s", proc.returncode, proc.stderr[:2000])
        return {
            "verdict": "SANDBOX_ERROR",
            "exit_code": proc.returncode,
            "stdout": "",
            "stderr": (proc.stderr or proc.stdout or "runner produced no output")[:4000],
        }


_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _make_scratch() -> tuple[str, str, str]:
    """Create a per-run scratch dir.

    Returns (run_id, host_source_dir, jail_dir). host_source_dir is where the
    gateway writes the source on the host; jail_dir is the path the jailed
    process sees that same directory at after pivot_root. In overlay mode the
    source goes into lower/ and the jail works in the merged/ view.
    """
    run_id = f"task_{uuid.uuid4().hex[:16]}"
    assert _SAFE_RUN_ID.match(run_id)
    scratch = os.path.join(ROOTFS_WORKSPACE, run_id)
    # 0700 for now; the runner chowns it to the sandbox uid before dropping
    # privileges, so the jailed process gets access without the directory ever
    # being world-writable.
    os.makedirs(scratch, mode=0o700, exist_ok=False)

    if OVERLAY:
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(scratch, sub), mode=0o700, exist_ok=False)
        host_source_dir = os.path.join(scratch, "lower")
        jail_dir = f"/{WORKSPACE_REL}/{run_id}/merged"
    else:
        host_source_dir = scratch
        jail_dir = f"/{WORKSPACE_REL}/{run_id}"
    return run_id, host_source_dir, jail_dir


def _cleanup(run_id: str) -> None:
    """Remove the whole per-run scratch tree.

    The runner's --cleanup stage has already emptied the writable surface and
    handed the top directory back to us, so this is normally a cheap rmtree.
    Anything left over is logged rather than swallowed: a silent failure here is
    how the disk fills up with undeletable sandbox output.
    """
    host_path = os.path.join(ROOTFS_WORKSPACE, run_id)
    errors: List[str] = []

    def onerror(_func, path, exc_info):
        errors.append(f"{path}: {exc_info[1]}")

    shutil.rmtree(host_path, onerror=onerror)
    if os.path.exists(host_path):
        log.error("could not clean scratch dir %s: %s", host_path, "; ".join(errors))


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {
        "ok": os.path.isfile(RUNNER_PATH) and os.path.isdir(ROOTFS_DIR),
        "runner": os.path.isfile(RUNNER_PATH),
        "rootfs": os.path.isdir(ROOTFS_DIR),
        "languages": sorted(LANGUAGES),
        "max_concurrent": MAX_CONCURRENT,
        "uid_pool": {"base": UID_POOL_BASE, "size": UID_POOL_SIZE},
        "overlay": OVERLAY,
        "auth_required": API_KEY is not None,
    }


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/execute", dependencies=[Depends(require_api_key)])
def execute_code(req: ExecutionRequest) -> Dict[str, Any]:
    if len(req.code.encode("utf-8", "ignore")) > MAX_CODE_BYTES:
        raise HTTPException(status_code=413, detail="code exceeds size limit")
    stdin_data = req.stdin or ""
    if len(stdin_data.encode("utf-8", "ignore")) > MAX_STDIN_BYTES:
        raise HTTPException(status_code=413, detail="stdin exceeds size limit")

    spec = LANGUAGES[req.language]

    # Acquiring an identity is the concurrency gate.
    try:
        uid, gid = _identities.get(timeout=30)
    except queue.Empty:
        raise HTTPException(status_code=503, detail="sandbox at capacity, retry shortly")
    M_SLOTS.inc()

    started = time.perf_counter()
    run_id, host_source_dir, jail_dir = _make_scratch()
    workdir_rel = f"{WORKSPACE_REL}/{run_id}"

    def expand(template: List[str]) -> List[str]:
        return [part.replace("{dir}", jail_dir) for part in template]

    try:
        with open(os.path.join(host_source_dir, spec["file"]), "w", encoding="utf-8") as f:
            f.write(req.code)

        if "compile" in spec:
            # Compile in its own jail; --cleanup is deliberately NOT passed here,
            # or it would delete the artifact we are about to execute.
            comp = _run_stage(
                expand(spec["compile"]),
                uid=uid, gid=gid, run_id=f"{run_id}c", workdir_rel=workdir_rel,
                timeout=COMPILE_TIMEOUT_SEC,
                mem_mb=spec.get("compile_mem", 384),
                pids=spec.get("compile_pids", 32),
                cleanup=False,
            )
            if comp.get("verdict") == "SANDBOX_ERROR":
                result = comp
            elif comp.get("exit_code") != 0:
                result = {
                    "verdict": "COMPILATION_ERROR",
                    "exit_code": comp.get("exit_code"),
                    "wall_time_ms": comp.get("wall_time_ms"),
                    "stdout": comp.get("stdout", ""),
                    "stderr": comp.get("stderr", ""),
                }
            else:
                result = _run_stage(
                    expand(spec["run"]),
                    uid=uid, gid=gid, run_id=run_id, workdir_rel=workdir_rel,
                    timeout=req.timeout_sec, mem_mb=req.mem_mb, pids=16,
                    cleanup=True, stdin_data=stdin_data,
                )
        else:
            result = _run_stage(
                expand(spec["run"]),
                uid=uid, gid=gid, run_id=run_id, workdir_rel=workdir_rel,
                timeout=req.timeout_sec, mem_mb=req.mem_mb, pids=16,
                cleanup=True, stdin_data=stdin_data,
            )

        _record(req.language, result, time.perf_counter() - started)
        return result
    finally:
        _cleanup(run_id)
        _identities.put((uid, gid))
        M_SLOTS.dec()


def _record(language: str, result: Dict[str, Any], e2e_seconds: float) -> None:
    M_EXEC.labels(language=language, verdict=result.get("verdict", "UNKNOWN")).inc()
    M_E2E.observe(e2e_seconds)
    wall = result.get("wall_time_ms")
    if isinstance(wall, (int, float)):
        M_WALL.observe(wall)
    peak = result.get("peak_memory_bytes")
    if isinstance(peak, (int, float)):
        M_PEAK.observe(peak)
