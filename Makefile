CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wpedantic -fstack-protector-strong \
            -D_FORTIFY_SOURCE=2
LDFLAGS  ?= -Wl,-z,relro,-z,now
LDLIBS   := -lseccomp

BIN      := sandbox_runner
SRC      := src/main.cpp
HOST     ?= 127.0.0.1
PORT     ?= 8000

.PHONY: all build bootstrap server test escape-tests bench audit-syscalls install-runner clean

all: build

build: $(BIN)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(SRC) $(LDLIBS) -o $@

bootstrap:
	chmod +x scripts/bootstrap_rootfs.sh
	./scripts/bootstrap_rootfs.sh

# The runner must be root-owned and not writable by the user who holds the
# NOPASSWD sudoers entry, or that entry is a local root escalation.
install-runner: $(BIN)
	sudo chown root:root $(BIN)
	sudo chmod 0755 $(BIN)
	sudo mkdir -p /sys/fs/cgroup/sandbox_demo

# Binds loopback by default. Set HOST=0.0.0.0 only behind an authenticating
# proxy, and set KHOROS_API_KEY when you do.
server:
	uvicorn api.server:app --host $(HOST) --port $(PORT)

test:
	chmod +x scripts/test_engine.sh
	./scripts/test_engine.sh

escape-tests:
	chmod +x scripts/escape_tests.sh
	./scripts/escape_tests.sh

bench:
	@echo "Not written yet. A credible bench needs: p50/p95/p99 over >=1000 runs,"
	@echo "kernel + CPU recorded, warm vs cold distinguished, and the same"
	@echo "workload run against nsjail / bubblewrap / isolate / Docker."
	@echo "Note that wall_time_ms is measured inside the runner and excludes the"
	@echo "sudo exec and HTTP handling, so report end-to-end latency separately."
	@false

# Record the syscalls a workload actually makes, to refine the seccomp
# allowlist. Run the jail with --seccomp log and read the denials from dmesg.
audit-syscalls:
	@echo "Run a workload with --seccomp log, then:"
	@echo "  sudo dmesg | grep -i seccomp | tail -50"
	@echo "Or trace a host-side equivalent:"
	@echo "  strace -f -c -o /tmp/khoros-strace.txt python3 -c 'print(1)'"

clean:
	rm -f $(BIN)
