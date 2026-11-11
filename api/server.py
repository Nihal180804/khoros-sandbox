"""Khoros Sandbox - FastAPI gateway.

Changes from the previous version, in order of importance:
  * Execution limits from the request body are clamped. Previously
    timeout_sec=0 reached alarm(0) and disabled the watchdog entirely.
  * json.loads of the runner output is guarded, so a runner failure returns a
    SANDBOX_ERROR verdict instead of an unhandled 500.
  * Concurrency is bounded by a semaphore, so N clients cannot spawn N jails.
  * An API key is required when KHOROS_API_KEY is set, and the documented bind
    address is 127.0.0.1.
  * Scratch directories are created 0700 and handed to the sandbox uid by the
    runner (via --workdir), instead of living in a world-writable workspace.
  * Scratch cleanup runs as a best effort and reports what it could not remove,
    rather than silently leaking undeletable root-owned subdirectories.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
import uuid
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
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
COMPILE_TIMEOUT_SEC = 15
COMPILE_MEM_MB = 384

API_KEY = os.environ.get("KHOROS_API_KEY")  # unset => no auth (localhost only)

# Unprivileged identity the jail runs as. bootstrap_rootfs.sh creates the
# khoros-sandbox user and prints these; 65534 (nobody) is the fallback.
SANDBOX_UID = os.environ.get("KHOROS_SANDBOX_UID", "65534")
SANDBOX_GID = os.environ.get("KHOROS_SANDBOX_GID", "65534")
if not (SANDBOX_UID.isdigit() and SANDBOX_GID.isdigit()):
    raise RuntimeError("KHOROS_SANDBOX_UID/GID must be numeric")
if SANDBOX_UID == "0" or SANDBOX_GID == "0":
    raise RuntimeError("refusing to run the sandbox as root")

IDENTITY_ARGS = ["--uid", SANDBOX_UID, "--gid", SANDBOX_GID]

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)

app = FastAPI(title="Khoros Sandbox Engine", version="2.0")


class ExecutionRequest(BaseModel):
    language: str = Field(pattern="^(python|cpp)$")
    code: str
    stdin: Optional[str] = ""
    timeout_sec: int = Field(default=2, ge=1, le=MAX_TIMEOUT_SEC)
    mem_mb: int = Field(default=64, ge=8, le=MAX_MEM_MB)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_KEY is None:
        return
    if x_api_key is None or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def _run_runner(args: list[str], stdin_data: str = "") -> Dict[str, Any]:
    """Invoke the C++ runner and parse its JSON telemetry.

    Never raises on malformed output: a runner that dies before printing JSON
    yields a SANDBOX_ERROR verdict carrying its stderr, which is far easier to
    debug than a FastAPI traceback.
    """
    cmd = ["sudo", "-n", RUNNER_PATH, *IDENTITY_ARGS, *args]
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


def _make_scratch() -> tuple[str, str]:
    """Create a per-run scratch dir. Returns (run_id, host_path)."""
    run_id = f"task_{uuid.uuid4().hex[:16]}"
    assert _SAFE_RUN_ID.match(run_id)
    host_path = os.path.join(ROOTFS_WORKSPACE, run_id)
    # 0700 for now; the runner chowns it to the sandbox uid before dropping
    # privileges, so the jailed process gets access without the directory ever
    # being world-writable.
    os.makedirs(host_path, mode=0o700, exist_ok=False)
    return run_id, host_path


def _cleanup(host_path: str) -> None:
    """Remove the scratch dir.

    The runner's --cleanup stage has already emptied the directory and handed
    it back to us, so this is normally just an rmdir. Anything left over is
    logged rather than swallowed: a silent failure here is how the disk fills
    up with undeletable sandbox output.
    """
    errors: list[str] = []

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
        "max_concurrent": MAX_CONCURRENT,
        "auth_required": API_KEY is not None,
    }


@app.post("/execute", dependencies=[Depends(require_api_key)])
def execute_code(req: ExecutionRequest) -> Dict[str, Any]:
    if len(req.code.encode("utf-8", "ignore")) > MAX_CODE_BYTES:
        raise HTTPException(status_code=413, detail="code exceeds size limit")
    stdin_data = req.stdin or ""
    if len(stdin_data.encode("utf-8", "ignore")) > MAX_STDIN_BYTES:
        raise HTTPException(status_code=413, detail="stdin exceeds size limit")

    if not _slots.acquire(blocking=True, timeout=30):
        raise HTTPException(status_code=503, detail="sandbox at capacity, retry shortly")

    run_id, scratch = _make_scratch()
    workdir_rel = f"{WORKSPACE_REL}/{run_id}"
    # Paths as the jailed process sees them after pivot_root. The runner
    # requires an absolute path for the executable so nothing is resolved
    # through PATH inside the jail.
    jail_dir = f"/{workdir_rel}"

    try:
        if req.language == "python":
            with open(os.path.join(scratch, "solution.py"), "w", encoding="utf-8") as f:
                f.write(req.code)
            return _run_runner(
                [
                    "--timeout", str(req.timeout_sec),
                    "--mem", str(req.mem_mb),
                    "--cgroup", run_id,
                    "--workdir", workdir_rel,
                    "--cleanup",
                    "/usr/bin/python3", f"{jail_dir}/solution.py",
                ],
                stdin_data,
            )

        # cpp: compile in one jail, execute the artifact in a second.
        # --cleanup is passed only on the execute stage; passing it on the
        # compile stage would delete the binary we are about to run.
        with open(os.path.join(scratch, "solution.cpp"), "w", encoding="utf-8") as f:
            f.write(req.code)

        comp = _run_runner([
            "--timeout", str(COMPILE_TIMEOUT_SEC),
            "--mem", str(COMPILE_MEM_MB),
            "--pids", "32",
            "--cgroup", f"{run_id}c",
            "--workdir", workdir_rel,
            "/usr/bin/g++", "-O2", "-std=c++17",
            f"{jail_dir}/solution.cpp", "-o", f"{jail_dir}/solution",
        ])

        if comp.get("verdict") == "SANDBOX_ERROR":
            return comp
        if comp.get("exit_code") != 0:
            return {
                "verdict": "COMPILATION_ERROR",
                "exit_code": comp.get("exit_code"),
                "wall_time_ms": comp.get("wall_time_ms"),
                "stdout": comp.get("stdout", ""),
                "stderr": comp.get("stderr", ""),
            }

        return _run_runner(
            [
                "--timeout", str(req.timeout_sec),
                "--mem", str(req.mem_mb),
                "--cgroup", run_id,
                "--workdir", workdir_rel,
                "--cleanup",
                f"{jail_dir}/solution",
            ],
            stdin_data,
        )
    finally:
        _cleanup(scratch)
        _slots.release()
