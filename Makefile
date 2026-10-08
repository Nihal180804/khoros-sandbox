CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
LDFLAGS ?= -lseccomp

TARGET = sandbox_runner
SRC = src/main.cpp

.PHONY: all build bootstrap server test clean help

all: build

build: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)
	@mkdir -p /sys/fs/cgroup/sandbox_demo 2>/dev/null || true

bootstrap:
	chmod +x scripts/bootstrap_rootfs.sh
	./scripts/bootstrap_rootfs.sh

server:
	uvicorn api.server:app --host 0.0.0.0 --port 8000

test:
	chmod +x scripts/test_engine.sh
	./scripts/test_engine.sh

clean:
	rm -f $(TARGET)

help:
	@echo "Khoros Sandbox Makefile Targets:"
	@echo "  make build      - Compile sandbox_runner binary (C++17, -lseccomp)"
	@echo "  make bootstrap  - Provision minimal Alpine rootfs with Python & GCC"
	@echo "  make server     - Start FastAPI backend server"
	@echo "  make test       - Run end-to-end sandbox verification test suite"
	@echo "  make clean      - Remove compiled sandbox runner binary"
