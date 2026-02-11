# SPDX-License-Identifier: GPL-2.0
# XDP DDoS Scrubber — Build System

CLANG       ?= clang
LLC         ?= llc
BPFTOOL     ?= bpftool
STRIP       ?= llvm-strip

# Directories
SRC_DIR     := src/bpf
BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj

# Kernel headers (adjust for your system)
KERNEL_HEADERS ?= /usr/include
LIBBPF_HEADERS ?= /usr/include

# BPF compilation flags
BPF_CFLAGS  := -g -O2 \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I$(SRC_DIR) \
    -I$(KERNEL_HEADERS) \
    -I$(LIBBPF_HEADERS) \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types

# Source files
XDP_SRC     := $(SRC_DIR)/xdp_main.c
XDP_OBJ     := $(OBJ_DIR)/xdp_ddos_scrubber.o
XDP_SKEL    := $(BUILD_DIR)/xdp_ddos_scrubber.skel.h

# All header dependencies
HEADERS     := $(wildcard $(SRC_DIR)/common/*.h) \
               $(wildcard $(SRC_DIR)/modules/*.h)

.PHONY: all clean skeleton install load unload status \
       build-go build-frontend build-all \
       docker docker-up docker-down \
       install-host uninstall-host

# ===== Default: BPF only =====
all: $(XDP_OBJ)

# ===== Full build (BPF + Go + Frontend) =====
build-all: $(XDP_OBJ) build-go build-frontend

build-go: $(XDP_OBJ)
	cd src/control-plane && $(MAKE) build

build-frontend:
	cd src/frontend && npm ci --ignore-scripts 2>/dev/null || cd src/frontend && npm install
	cd src/frontend && npm run build

# ===== Docker =====
docker:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-monitoring:
	docker compose --profile monitoring up -d

# ===== Host install (bare-metal) =====
install-host: build-all
	sudo ./deploy/scripts/install.sh --interface $(IFACE) --mode $(MODE)

uninstall-host:
	sudo ./deploy/scripts/uninstall.sh

# ===== Testing =====
test: test-unit

test-unit:
	cd src/control-plane && go test -v -race -count=1 ./...

test-bpf: $(XDP_OBJ)
	cd tests/bpf && $(MAKE) test

test-integration:
	bash tests/integration/test_pipeline.sh

test-api:
	bash tests/integration/test_api.sh

test-all:
	bash tests/run_all.sh --all

bench:
	cd src/control-plane && go test -bench=. -benchmem ./...

bench-xdp: $(XDP_OBJ)
	sudo bash tests/performance/bench_xdp.sh

# Generate test pcap fixtures (requires scapy)
gen-fixtures:
	python3 tests/fixtures/attack_packets.py tests/fixtures/pcap

# Create build directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile BPF object
$(XDP_OBJ): $(XDP_SRC) $(HEADERS) | $(OBJ_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(STRIP) -g $@

# Generate BPF skeleton header (for Go/C userspace)
skeleton: $(XDP_SKEL)

$(XDP_SKEL): $(XDP_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Load XDP program onto an interface
# Usage: make load IFACE=eth0 [MODE=native|skb]
IFACE ?= eth0
MODE  ?= native

load: $(XDP_OBJ)
	@echo "Loading XDP program on $(IFACE) (mode: $(MODE))..."
	@if [ "$(MODE)" = "native" ]; then \
		ip link set dev $(IFACE) xdpgeneric off 2>/dev/null; \
		ip link set dev $(IFACE) xdp obj $(XDP_OBJ) sec xdp; \
	elif [ "$(MODE)" = "skb" ]; then \
		ip link set dev $(IFACE) xdp off 2>/dev/null; \
		ip link set dev $(IFACE) xdpgeneric obj $(XDP_OBJ) sec xdp; \
	fi
	@echo "Done. Use 'make status IFACE=$(IFACE)' to verify."

# Unload XDP program
unload:
	@echo "Unloading XDP program from $(IFACE)..."
	ip link set dev $(IFACE) xdp off 2>/dev/null || true
	ip link set dev $(IFACE) xdpgeneric off 2>/dev/null || true
	@echo "Done."

# Show XDP program status
status:
	@echo "=== Interface $(IFACE) ==="
	ip link show dev $(IFACE) | head -3
	@echo ""
	@echo "=== Loaded BPF programs ==="
	bpftool prog show 2>/dev/null | grep -A2 xdp || echo "No XDP programs loaded"
	@echo ""
	@echo "=== BPF Maps ==="
	bpftool map show 2>/dev/null | head -20 || echo "No BPF maps"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Install dependencies (Ubuntu/Debian)
install-deps:
	apt-get update && apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$$(uname -r) \
		bpftool \
		iproute2 \
		make

# Verify toolchain
check-tools:
	@echo "Checking build tools..."
	@which $(CLANG)   >/dev/null 2>&1 && echo "  clang:   OK" || echo "  clang:   MISSING"
	@which $(LLC)     >/dev/null 2>&1 && echo "  llc:     OK" || echo "  llc:     MISSING"
	@which $(BPFTOOL) >/dev/null 2>&1 && echo "  bpftool: OK" || echo "  bpftool: MISSING"
	@which $(STRIP)   >/dev/null 2>&1 && echo "  strip:   OK" || echo "  strip:   MISSING"
	@uname -r
