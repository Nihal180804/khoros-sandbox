#!/usr/bin/env bash
#
# Khoros Sandbox - smoke tests.
#
# Functional sanity only. The security assertions live in escape_tests.py;
# run both (make test && make escape-tests).
#
# Note the verdict rename: TIME_OR_MEMORY_LIMIT_EXCEEDED was ambiguous and is
# now TIME_LIMIT_EXCEEDED or MEMORY_LIMIT_EXCEEDED, decided by the cgroup's
# memory.events oom_kill counter.

set -uo pipefail

URL="${KHOROS_URL:-http://127.0.0.1:8000}"
ROOTFS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rootfs"
PASS=0
FAIL=0

# A runtime is only testable if its interpreter/compiler is in the rootfs. The
# gateway advertises every language regardless, so guard the new-runtime cases
# here rather than letting them fail as SANDBOX_ERROR on a minimal rootfs.
has_rt() { [ -x "${ROOTFS}/usr/bin/$1" ]; }

check() {
    local name="$1"; shift
    local body="$1"; shift
    local py="$1"; shift

    local resp
    resp="$(curl -sS -X POST "${URL}/execute" \
        -H 'Content-Type: application/json' \
        ${KHOROS_API_KEY:+-H "X-API-Key: ${KHOROS_API_KEY}"} \
        -d "${body}" 2>&1)" || resp=''

    if printf '%s' "${resp}" | python3 -c "
import json,sys
try: r = json.load(sys.stdin)
except Exception as e:
    print('   not JSON:', e); sys.exit(1)
sys.exit(0 if (${py}) else (print('   got:', json.dumps(r)[:300]) or 1))
"; then
        echo "[PASS] ${name}"; PASS=$((PASS+1))
    else
        echo "[FAIL] ${name}"; FAIL=$((FAIL+1))
    fi
}

echo "=== Khoros smoke tests against ${URL} ==="

# Server reachable at all?
if ! curl -fsS "${URL}/healthz" >/dev/null 2>&1; then
    echo "[!] cannot reach ${URL}/healthz - start the server with 'make server'"
    exit 1
fi
curl -fsS "${URL}/healthz"; echo

check "python execution" \
    '{"language":"python","code":"print(2 + 2)"}' \
    'r["verdict"] == "OK" and "4" in r["stdout"]'

check "python stdin passthrough" \
    '{"language":"python","code":"import sys; print(sum(int(x) for x in sys.stdin))","stdin":"1\n2\n3\n"}' \
    'r["verdict"] == "OK" and "6" in r["stdout"]'

check "python runtime error -> NON_ZERO_EXIT" \
    '{"language":"python","code":"1/0"}' \
    'r["verdict"] == "NON_ZERO_EXIT" and "ZeroDivisionError" in r["stderr"]'

check "unicode output survives JSON encoding" \
    '{"language":"python","code":"print(\"àéî 日本語\")"}' \
    'r["verdict"] == "OK" and "日本語" in r["stdout"]'

check "binary output does not break the API" \
    '{"language":"python","code":"import sys; sys.stdout.buffer.write(bytes(range(256)))"}' \
    'r["verdict"] == "OK"'

check "watchdog -> TIME_LIMIT_EXCEEDED" \
    '{"language":"python","code":"while True: pass","timeout_sec":1}' \
    'r["verdict"] == "TIME_LIMIT_EXCEEDED"'

check "memory ceiling -> MEMORY_LIMIT_EXCEEDED" \
    '{"language":"python","code":"x = bytearray(300*1024*1024)","mem_mb":64}' \
    'r["verdict"] == "MEMORY_LIMIT_EXCEEDED"'

check "network blocked by seccomp" \
    '{"language":"python","code":"import socket; socket.socket()"}' \
    '"Operation not permitted" in r["stderr"]'

check "cpp compile and run" \
    '{"language":"cpp","code":"#include <iostream>\n#include <vector>\n#include <numeric>\nint main(){std::vector<int> v={1,2,3,4,5};std::cout<<\"Sum: \"<<std::accumulate(v.begin(),v.end(),0)<<std::endl;}"}' \
    'r["verdict"] == "OK" and "Sum: 15" in r["stdout"]'

check "cpp compile error -> COMPILATION_ERROR" \
    '{"language":"cpp","code":"int main(){ return nope; }"}' \
    'r["verdict"] == "COMPILATION_ERROR"'

check "threads work inside the jail" \
    '{"language":"python","code":"import threading\nout=[]\nt=threading.Thread(target=lambda: out.append(1))\nt.start(); t.join()\nprint(\"threads\", len(out))"}' \
    'r["verdict"] == "OK" and "threads 1" in r["stdout"]'

check "/dev/null and /dev/urandom exist" \
    '{"language":"python","code":"open(\"/dev/null\",\"w\").write(\"x\")\nprint(\"rand\", len(open(\"/dev/urandom\",\"rb\").read(8)))"}' \
    'r["verdict"] == "OK" and "rand 8" in r["stdout"]'

check "rejects out-of-range timeout" \
    '{"language":"python","code":"print(1)","timeout_sec":9999}' \
    'r.get("verdict") != "OK"'

# ---------------- additional runtimes (skipped if not in the rootfs) ----------
if has_rt node; then
    check "node execution" \
        '{"language":"node","code":"console.log(6*7)"}' \
        'r["verdict"] == "OK" and "42" in r["stdout"]'
else
    echo "[skip] node execution (no /usr/bin/node in rootfs)"
fi

if has_rt rustc; then
    check "rust compile and run" \
        '{"language":"rust","code":"fn main(){ println!(\"rust {}\", 2+2); }"}' \
        'r["verdict"] == "OK" and "rust 4" in r["stdout"]'
    check "rust compile error -> COMPILATION_ERROR" \
        '{"language":"rust","code":"fn main(){ let x: i32 = \"nope\"; }"}' \
        'r["verdict"] == "COMPILATION_ERROR"'
else
    echo "[skip] rust (no /usr/bin/rustc in rootfs)"
fi

if has_rt go; then
    check "go compile and run" \
        '{"language":"go","code":"package main\nimport \"fmt\"\nfunc main(){ fmt.Println(\"go\", 3*3) }"}' \
        'r["verdict"] == "OK" and "go 9" in r["stdout"]'
else
    echo "[skip] go (no /usr/bin/go in rootfs)"
fi

# ---------------- per-run uid pool: concurrent runs get distinct ids ----------
echo "[....] per-run uid isolation (two concurrent requests)"
UID_BODY='{"language":"python","code":"import os,time; time.sleep(0.4); print(os.getuid())","timeout_sec":5}'
TMPA="$(mktemp)"; TMPB="$(mktemp)"
curl -sS -X POST "${URL}/execute" -H 'Content-Type: application/json' \
    ${KHOROS_API_KEY:+-H "X-API-Key: ${KHOROS_API_KEY}"} -d "${UID_BODY}" >"${TMPA}" &
curl -sS -X POST "${URL}/execute" -H 'Content-Type: application/json' \
    ${KHOROS_API_KEY:+-H "X-API-Key: ${KHOROS_API_KEY}"} -d "${UID_BODY}" >"${TMPB}" &
wait
if python3 -c "
import json,sys
a=json.load(open('${TMPA}')); b=json.load(open('${TMPB}'))
ua=(a.get('stdout') or '').strip(); ub=(b.get('stdout') or '').strip()
ok = ua.isdigit() and ub.isdigit() and ua != ub
print('   uids:', ua, ub)
sys.exit(0 if ok else 1)
"; then
    echo "[PASS] per-run uid isolation"; PASS=$((PASS+1))
else
    echo "[FAIL] per-run uid isolation (expected two different uids)"; FAIL=$((FAIL+1))
fi
rm -f "${TMPA}" "${TMPB}"

echo
echo "=== ${PASS} passed, ${FAIL} failed ==="
[ "${FAIL}" -eq 0 ]
