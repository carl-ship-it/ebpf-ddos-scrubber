# eBPF DDoS Scrubber

High-performance L3/L4 DDoS traffic scrubbing appliance built on Linux XDP/eBPF. Processes packets at line rate in the kernel's XDP hook before they reach the network stack, achieving multi-million packets per second on commodity hardware.

Comparable to commercial solutions from Arbor Networks, Imperva, and Radware — but open-source.

## Architecture

```
                         ┌─────────────────────────────────┐
                         │        React Dashboard          │
                         │   (Ant Design 5 + ECharts)      │
                         └──────────┬──────────────────────┘
                                    │ REST / WebSocket
                         ┌──────────▼──────────────────────┐
                         │      Go Control Plane            │
                         │  (cilium/ebpf + gRPC + Zap)     │
                         └──────────┬──────────────────────┘
                                    │ BPF Maps
┌───────────────────────────────────▼──────────────────────────────────┐
│                        XDP Data Plane (Kernel)                       │
│                                                                      │
│  Parse → ACL → Fragment → Fingerprint → SYN Cookie → ACK Flood      │
│  → UDP Flood → ICMP Flood → Per-Source Rate Limit → Global Rate      │
│  → Conntrack → XDP_PASS                                              │
└──────────────────────────────────────────────────────────────────────┘
```

## Features

**Data Plane (XDP/eBPF)**
- 12-stage packet processing pipeline
- SYN Cookie challenge-response (SipHash-2-4)
- Per-source + global token bucket rate limiting (lock-free, per-CPU)
- DNS / NTP / SSDP / Memcached amplification detection
- IP blacklist/whitelist via LPM Trie (CIDR matching)
- Lightweight connection tracking (TCP state machine + UDP/ICMP)
- IP fragment attack filtering
- Attack signature fingerprint matching (up to 64 rules)
- Ring buffer event streaming to userspace

**Control Plane (Go)**
- BPF program loading via cilium/ebpf
- gRPC API with 12 RPCs (status, stats, ACL, rate config, conntrack, signatures, events)
- Per-CPU stats aggregation with PPS/BPS rate computation
- SYN cookie seed rotation (configurable interval)
- YAML configuration with runtime updates

**Frontend (React)**
- Real-time dashboard with traffic charts (PPS/BPS)
- Attack type breakdown (pie chart)
- SYN cookie success rate panel
- ACL management (blacklist/whitelist CIDR)
- Rate limit configuration
- Attack signature editor
- Event log with filtering
- Dark theme (Ant Design 5)

## Quick Start

### Docker (Recommended)

```bash
# Build and start all services
docker compose build
docker compose up -d

# With Grafana monitoring
docker compose --profile monitoring up -d
```

Dashboard: http://localhost:8080
API: http://localhost:9090

### Bare Metal

```bash
# Prerequisites (Ubuntu 24.04)
make install-deps

# Build everything
make build-all

# Install and start
sudo make install-host IFACE=eth0 MODE=native
sudo systemctl start ddos-scrubber
```

### Development

```bash
# BPF only
make all

# Go control plane
cd src/control-plane && make build

# Frontend
cd src/frontend && npm install && npm run dev
```

## Project Structure

```
├── src/
│   ├── bpf/                    # XDP data plane (C)
│   │   ├── common/             #   types, maps, helpers, parser
│   │   ├── modules/            #   attack mitigation modules (9)
│   │   └── xdp_main.c          #   entry point
│   ├── control-plane/          # Go control plane
│   │   ├── cmd/scrubber/       #   main entry point
│   │   ├── internal/           #   bpf, config, stats, events, api, engine
│   │   └── api/proto/          #   gRPC protobuf definition
│   └── frontend/               # React dashboard
│       └── src/                #   pages, components, hooks, store, api
├── tests/
│   ├── bpf/                    # BPF_PROG_TEST_RUN harness (C)
│   ├── integration/            # API + pipeline tests (bash)
│   ├── performance/            # XDP + Go benchmarks
│   └── fixtures/               # Scapy attack packet generator
├── deploy/
│   ├── docker/                 # Dockerfiles + nginx config
│   ├── systemd/                # systemd service unit
│   └── scripts/                # install / uninstall scripts
├── configs/config.yaml         # Default configuration
├── docker-compose.yml          # Full stack (CP + UI + VictoriaMetrics + Redis)
├── Makefile                    # Top-level build system
└── .github/workflows/          # CI + Release + Security scanning
```

## Testing

```bash
make test           # Go unit tests
make test-bpf       # BPF XDP tests (requires root)
make test-api       # REST API integration tests
make test-all       # All tests
make bench          # Go benchmarks
make bench-xdp      # XDP per-packet benchmarks (requires root)
make gen-fixtures   # Generate attack pcap fixtures (requires scapy)
```

## Configuration

Edit `configs/config.yaml` or `/etc/ddos-scrubber/config.yaml`:

```yaml
interface: eth0
xdp_mode: native          # native | skb | offload

scrubber:
  enabled: true
  conntrack_enabled: true

syn_cookie:
  enabled: true
  seed_rotation_sec: 60

rate_limit:
  syn_rate_pps: 1000       # Per-source SYN limit
  udp_rate_pps: 10000      # Per-source UDP limit
  icmp_rate_pps: 100       # Per-source ICMP limit
  global_pps: 0            # 0 = disabled
  global_bps: 0

blacklist: []              # CIDR list
whitelist: []              # CIDR list
```

## Requirements

- Linux kernel >= 5.15 (6.1+ recommended for best XDP support)
- clang/llvm >= 15
- libbpf-dev
- Go >= 1.22
- Node.js >= 20
- NIC with XDP native mode support (Intel E810, Mellanox ConnectX-5+) for best performance

## License

GPL-2.0
