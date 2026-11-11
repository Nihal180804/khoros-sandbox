#!/usr/bin/env python3
"""Khoros Sandbox - adversarial test suite.

Every case here corresponds to a specific escape or resource-exhaustion path.
A green run is the evidence behind the word "hardened" in the README; without
it that word is a claim rather than a result.

Usage:
    python3 scripts/escape_tests.py [--url http://127.0.0.1:8000] [-v]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

DEFAULT_URL = "http://127.0.0.1:8000"


def post(url: str, payload: dict, api_key: Optional[str], timeout: int = 90) -> dict:
    req = urllib.request.Request(
        f"{url}/execute",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 **({"X-API-Key": api_key} if api_key else {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"verdict": f"HTTP_{e.code}", "stderr": e.read().decode("utf-8", "replace")}


@dataclass
class Case:
    name: str
    why: str                      # the threat this case covers
    code: str
    check: Callable[[dict], bool]
    language: str = "python"
    timeout_sec: int = 5
    mem_mb: int = 64


def out(r: dict) -> str:
    return (r.get("stdout") or "") + (r.get("stderr") or "")


CASES: list[Case] = [
    # ---------------- privilege ----------------
    Case(
        "not running as root",
        "root in the initial user namespace makes pivot_root a weak boundary",
        'import os; print("UID", os.getuid(), "GID", os.getgid())',
        lambda r: "UID 0 " not in out(r) and "UID" in out(r),
    ),
    Case(
        "no effective capabilities",
        "CAP_SYS_ADMIN / CAP_MKNOD / CAP_SYS_MODULE each give a full escape",
        'print([l for l in open("/proc/self/status") if l.startswith("Cap")])',
        lambda r: "CapEff:\\t0000000000000000" in out(r)
                  or "CapEff:\t0000000000000000" in out(r),
    ),
    Case(
        "cannot regain uid 0",
        "a retained setuid capability would undo the whole privilege drop",
        'import os\ntry:\n os.setuid(0); print("ESCAPED")\nexcept Exception as e: print("blocked", type(e).__name__)',
        lambda r: "ESCAPED" not in out(r),
    ),

    # ---------------- host takeover paths ----------------
    Case(
        "core_pattern not writable",
        "writing |/path to core_pattern runs that helper as root on the host",
        'try:\n open("/proc/sys/kernel/core_pattern","w").write("|/tmp/x"); print("ESCAPED")\nexcept Exception as e: print("blocked", type(e).__name__)',
        lambda r: "ESCAPED" not in out(r),
    ),
    Case(
        "mknod refused",
        "a block device node plus mount reads the host disk directly",
        'import ctypes; rc = ctypes.CDLL(None, use_errno=True).mknod(b"/tmp/disk", 0o060600, 0x800)\nprint("mknod rc", rc)',
        lambda r: "mknod rc 0" not in out(r),
    ),
    Case(
        "mount refused",
        "CAP_SYS_ADMIN in a mount namespace means arbitrary host mounts",
        'import ctypes; print("mount rc", ctypes.CDLL(None).mount(b"none", b"/tmp", b"tmpfs", 0, None))',
        lambda r: "mount rc 0" not in out(r),
    ),
    Case(
        "new mount API refused",
        "fsopen/fsconfig/fsmount bypass a filter that only denies mount()",
        'import ctypes; print("fsopen rc", ctypes.CDLL(None).syscall(430, b"tmpfs", 0))',
        lambda r: "fsopen rc 0" not in out(r) and "fsopen rc -1" in out(r),
    ),
    Case(
        "kernel module load refused",
        "finit_module is unconditional host compromise",
        'import ctypes; print("finit rc", ctypes.CDLL(None).syscall(313, 0, b"", 0))',
        lambda r: "finit rc 0" not in out(r),
    ),
    Case(
        "io_uring refused",
        "io_uring submits file ops asynchronously, around syscall filters",
        'import ctypes; print("io_uring rc", ctypes.CDLL(None).syscall(425, 1, 0))',
        lambda r: "io_uring rc 0" not in out(r),
    ),
    Case(
        "bpf refused",
        "bpf() is a large kernel attack surface",
        'import ctypes; print("bpf rc", ctypes.CDLL(None).syscall(321, 0, 0, 0))',
        lambda r: "bpf rc 0" not in out(r),
    ),
    Case(
        "unshare refused",
        "nesting namespaces can re-acquire capabilities over new resources",
        'import ctypes; print("unshare rc", ctypes.CDLL(None).unshare(0x10000000))',
        lambda r: "unshare rc 0" not in out(r),
    ),
    Case(
        "ptrace refused",
        "ptrace against a more privileged process escapes the sandbox",
        'import ctypes; print("ptrace rc", ctypes.CDLL(None).ptrace(0, 1, 0, 0))',
        lambda r: "ptrace rc 0" not in out(r),
    ),

    # ---------------- filesystem ----------------
    Case(
        "rootfs is read-only",
        "a writable shared rootfs lets one run backdoor every later run",
        'try:\n open("/usr/bin/python3","ab").write(b"x"); print("ESCAPED")\nexcept Exception as e: print("blocked", type(e).__name__)',
        lambda r: "ESCAPED" not in out(r),
    ),
    Case(
        "cannot write outside workspace and /tmp",
        "persistence and host disk fill-up",
        'try:\n open("/etc/khoros_probe","w").write("x"); print("ESCAPED")\nexcept Exception as e: print("blocked", type(e).__name__)',
        lambda r: "ESCAPED" not in out(r),
    ),
    Case(
        "/proc/1/root does not expose the host",
        "a leaked host root under /proc defeats pivot_root entirely",
        # The leaf is PID 1 of its own pid namespace, so /proc/1 is this very
        # process and /proc/1/root should be the jail's own root. Merely
        # counting entries cannot tell that apart from a host leak, so compare
        # it against our own / and look for distro markers that only the host
        # would have.
        'import os\n'
        'try:\n'
        '    mine = sorted(os.listdir("/etc"))\n'
        '    seen = sorted(os.listdir("/proc/1/root/etc"))\n'
        # Markers below are files no Alpine minirootfs contains. Alpine ships
        # its own /etc/fstab and may ship /etc/sudoers, so neither of those is
        # a host marker -- using them produced a false positive.
        '    host = [p for p in ("arch-release", "pacman.conf", "makepkg.conf",\n'
        '                        "debian_version", "redhat-release", "fedora-release")\n'
        '            if os.path.exists("/proc/1/root/etc/" + p)]\n'
        '    print("same_as_jail", seen == mine)\n'
        '    print("alpine", os.path.exists("/proc/1/root/etc/alpine-release"))\n'
        '    print("host_markers", host)\n'
        'except Exception as e:\n'
        '    print("blocked", type(e).__name__)',
        lambda r: "blocked" in out(r)
                  or ("same_as_jail True" in out(r) and "host_markers []" in out(r)),
    ),
    Case(
        "pid namespace is isolated",
        "visibility of host pids enables targeted signalling and recon",
        'import os; pids=[p for p in os.listdir("/proc") if p.isdigit()]; print("npids", len(pids))',
        lambda r: any(f"npids {n}" in out(r) for n in range(1, 8)),
    ),

    # ---------------- network ----------------
    Case(
        "socket creation refused",
        "data exfiltration and reverse shells",
        'import socket\ntry:\n socket.socket(); print("ESCAPED")\nexcept Exception as e: print("blocked", type(e).__name__)',
        lambda r: "ESCAPED" not in out(r),
    ),

    # ---------------- resource exhaustion ----------------
    Case(
        "fork bomb contained",
        "pid exhaustion takes down the host, not just the run",
        'import os\nn=0\ntry:\n while n < 5000:\n  if os.fork()==0: os._exit(0)\n  n+=1\nexcept Exception: pass\nprint("forked", n)',
        lambda r: r.get("verdict") in {"OK", "NON_ZERO_EXIT", "TIME_LIMIT_EXCEEDED",
                                       "MEMORY_LIMIT_EXCEEDED", "KILLED"},
        timeout_sec=5,
    ),
    Case(
        "memory ceiling enforced",
        "a cgroup limit that silently failed to apply is worse than none",
        'x = bytearray(400 * 1024 * 1024); print("allocated", len(x))',
        lambda r: r.get("verdict") == "MEMORY_LIMIT_EXCEEDED"
                  or "allocated" not in out(r),
        mem_mb=64,
    ),
    Case(
        "wall clock timeout enforced",
        "the watchdog is the only bound on a spinning program",
        "while True: pass",
        lambda r: r.get("verdict") == "TIME_LIMIT_EXCEEDED",
        timeout_sec=2,
    ),
    Case(
        "stderr flood does not deadlock",
        "regression: draining stdout before stderr hung on >64KB of stderr",
        'import sys\nfor i in range(200000): sys.stderr.write("x"*64 + "\\n")\nprint("done")',
        lambda r: r.get("verdict") in {"OK", "NON_ZERO_EXIT"}
                  and r.get("stderr_truncated") is True,
        timeout_sec=20,
    ),
    Case(
        "stdout flood is capped",
        "unbounded capture buffers exhaust host memory",
        'import sys\nfor i in range(200000): sys.stdout.write("y"*64 + "\\n")',
        lambda r: r.get("stdout_truncated") is True
                  and len(r.get("stdout") or "") <= 2 * 1024 * 1024,
        timeout_sec=20,
    ),
    Case(
        "client cannot disable the watchdog",
        "timeout_sec=0 previously reached alarm(0) and removed the limit",
        "while True: pass",
        lambda r: r.get("verdict") in {"TIME_LIMIT_EXCEEDED", "HTTP_422"},
        timeout_sec=0,
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    print(f"=== Khoros adversarial suite ({len(CASES)} cases) against {args.url} ===\n")
    failures: list[str] = []

    for c in CASES:
        payload = {
            "language": c.language,
            "code": c.code,
            "timeout_sec": c.timeout_sec,
            "mem_mb": c.mem_mb,
        }
        try:
            r = post(args.url, payload, args.api_key)
            ok = bool(c.check(r))
        except Exception as e:                       # noqa: BLE001
            r, ok = {"verdict": f"HARNESS_ERROR: {e}"}, False

        print(f"[{'PASS' if ok else 'FAIL'}] {c.name}")
        if not ok:
            failures.append(c.name)
            print(f"       threat : {c.why}")
            print(f"       verdict: {r.get('verdict')}")
            print(f"       output : {out(r)[:300]!r}")
        elif args.verbose:
            print(f"       verdict: {r.get('verdict')}  output: {out(r)[:120]!r}")

    print()
    if failures:
        print(f"=== {len(failures)}/{len(CASES)} FAILED: {', '.join(failures)} ===")
        return 1
    print(f"=== all {len(CASES)} cases passed ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
