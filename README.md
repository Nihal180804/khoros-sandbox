# Khoros: Sub-40ms Hardened Linux Code Execution Sandbox

A low-latency, container-less sandboxed execution engine built in C++17 and Python for safely running untrusted, AI-generated code.

## Architecture
- **Filesystem Virtualization**: \`pivot_root\` into minimal Alpine rootfs with ephemeral \`tmpfs\` scratchpad.
- **Network Isolation**: \`CLONE_NEWNET\` namespace unsharing coupled with Seccomp-BPF filters blocking \`socket\` and \`connect\`.
- **Resource Caps (cgroups v2)**: Hard memory ceiling, swap disabled (\`memory.swap.max = 0\`), and strict PID limit to eliminate fork bombs.
- **Deterministic Watchdog**: Asynchronous parent timer utilizing \`cgroup.kill\` to prevent runaway loops without orphan leaks.

## Cold-Start Latency
- Python 3: **~35 ms**
- C++ Compiled Binary: **~15 ms**

## Quickstart
\`\`\`bash
g++ -O2 -std=c++17 src/main.cpp -lseccomp -o sandbox_runner
uvicorn api.server:app --host 127.0.0.1 --port 8000
\`\`\`
