#!/usr/bin/env bash
set -e

echo "=== Khoros Sandbox Test Suite ==="

# 1. Basic Python
echo -n "[Test 1] Python execution: "
python3 -c '
import requests
r = requests.post("http://127.0.0.1:8000/execute", json={"language": "python", "code": "print(2 + 2)"})
assert r.json()["verdict"] == "OK" and "4" in r.json()["stdout"]
' && echo "PASS"

# 2. Timeout watchdog
echo -n "[Test 2] Watchdog TLE (1s): "
python3 -c '
import requests
r = requests.post("http://127.0.0.1:8000/execute", json={"language": "python", "code": "while True: pass", "timeout_sec": 1})
assert r.json()["verdict"] == "TIME_OR_MEMORY_LIMIT_EXCEEDED"
' && echo "PASS"

# 3. Network egress block
echo -n "[Test 3] Seccomp network block: "
python3 -c '
import requests
r = requests.post("http://127.0.0.1:8000/execute", json={"language": "python", "code": "import socket; socket.socket()"})
assert "Operation not permitted" in r.json()["stderr"]
' && echo "PASS"

echo "=== All tests passed cleanly ==="