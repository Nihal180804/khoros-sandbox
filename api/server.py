import os
import subprocess
import json
import uuid
import shutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Khoros Sandbox Engine")

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOTFS_WORKSPACE = os.path.join(ENGINE_DIR, "rootfs/workspace")
RUNNER_PATH = os.path.join(ENGINE_DIR, "sandbox_runner")

class ExecutionRequest(BaseModel):
    language: str
    code: str
    stdin: Optional[str] = ""
    timeout_sec: int = 2
    mem_mb: int = 64

@app.post("/execute")
def execute_code(req: ExecutionRequest):
    run_id = f"task_{uuid.uuid4().hex[:8]}"
    scratch_dir = os.path.join(ROOTFS_WORKSPACE, run_id)
    os.makedirs(scratch_dir, exist_ok=True)

    try:
        if req.language == "python":
            script_path = os.path.join(scratch_dir, "solution.py")
            with open(script_path, "w") as f:
                f.write(req.code)

            jail_script = f"/workspace/{run_id}/solution.py"
            cmd = [
                "sudo", RUNNER_PATH,
                "--timeout", str(req.timeout_sec),
                "--mem", str(req.mem_mb),
                "--cgroup", run_id,
                "/usr/bin/python3", jail_script
            ]

        elif req.language == "cpp":
            src_path = os.path.join(scratch_dir, "solution.cpp")
            with open(src_path, "w") as f:
                f.write(req.code)

            jail_src = f"/workspace/{run_id}/solution.cpp"
            jail_bin = f"/workspace/{run_id}/solution"

            compile_cmd = [
                "sudo", RUNNER_PATH,
                "--timeout", "10",
                "--mem", "256",
                "--cgroup", f"{run_id}_compile",
                "/usr/bin/g++", jail_src, "-O2", "-o", jail_bin
            ]
            comp_res = subprocess.run(compile_cmd, cwd=ENGINE_DIR, capture_output=True, text=True)
            try:
                comp_data = json.loads(comp_res.stdout)
                if comp_data.get("exit_code") != 0:
                    return {
                        "verdict": "COMPILATION_ERROR",
                        "exit_code": comp_data.get("exit_code"),
                        "stdout": comp_data.get("stdout"),
                        "stderr": comp_data.get("stderr")
                    }
            except Exception:
                raise HTTPException(
                    status_code=500,
                    detail=f"Compiler error. STDOUT: {comp_res.stdout}, STDERR: {comp_res.stderr}"
                )

            cmd = [
                "sudo", RUNNER_PATH,
                "--timeout", str(req.timeout_sec),
                "--mem", str(req.mem_mb),
                "--cgroup", run_id,
                jail_bin
            ]
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported language: {req.language}")

        # Pipe stdin into the process if provided
        result = subprocess.run(
            cmd,
            cwd=ENGINE_DIR,
            input=req.stdin,
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)

    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)