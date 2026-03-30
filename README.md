# NexusWAF — Rust Core

**Advanced Web Application Firewall · Group AA3 · Framework Engineering College**

---

## Overview

This directory contains the full Rust data plane and control plane for NexusWAF. It runs the reverse proxy, executes the layered request pipeline, exposes operator APIs, persists attack/config data, and integrates with the RL policy service from `nexus-ml`.

**Gateway:** Axum/Hyper reverse proxy  
**Pipeline:** rate limit · lexical · grammar · rules · anomaly · policy · optional semantic ML  
**Control Plane:** REST + gRPC + metrics endpoints  
**Runtime Features:** GPS rule synthesis · Slack alerting · TLS/Certbot · PostgreSQL-backed logs

---

## Directory Structure

```text
nexus-core/
├── config/
│   ├── default.toml            # Main runtime config
│   └── rules.toml              # Active ruleset loaded by nexus-rules
├── proto/
│   └── policy.proto            # Shared gRPC contract with nexus-ml
├── nexus-gateway/
│   ├── src/main.rs             # CLI entrypoint
│   ├── src/server.rs           # HTTP/HTTPS, REST, gRPC, metrics servers
│   ├── src/proxy.rs            # Reverse proxy + verdict handling
│   ├── src/state.rs            # Shared app state + reload/runtime wiring
│   ├── src/alerting.rs         # Slack alert delivery
│   └── src/tls.rs              # Static TLS + Certbot runtime
├── nexus-control/
│   ├── src/http.rs             # REST control-plane routes
│   ├── src/server.rs           # gRPC control services
│   ├── src/ops.rs              # Stats, GPS, policy ops, rules/config actions
│   └── src/stats.rs            # API response models
├── nexus-pipeline/
│   └── src/pipeline.rs         # Layer execution order and final verdict logic
├── nexus-policy/
│   ├── src/lib.rs              # RL policy layer + gRPC client
│   ├── src/proto.rs            # Generated tonic bindings
│   └── build.rs                # Proto compilation
├── nexus-ml-client/            # Semantic ML client/layer (optional path)
├── nexus-lex/                  # Signature / regex scanner
├── nexus-grammar/              # Grammar / parser-based inspection
├── nexus-rules/                # TOML rule engine
├── nexus-anomaly/              # Baseline / anomaly detection
├── nexus-rate/                 # Per-IP rate limiting
├── nexus-lb/                   # Upstream health checks + balancing
├── nexus-store/                # PostgreSQL / Influx persistence
├── nexus-metrics/              # Prometheus exporter
├── nexus-telemetry/            # Policy telemetry window for adaptive control
├── nexus-config/               # Config schema, loader, env overrides
└── Cargo.toml                  # Workspace manifest
```

---

## Quick Start (5 steps)

### Prerequisites

- Rust stable toolchain
- PostgreSQL running for `attack_logs`, ruleset versions, and config events
- Optional: InfluxDB for time-series metrics
- Optional: Python `nexus-ml` policy service on `127.0.0.1:50052`

```bash
cd nexus-core/
cargo build
```

### Step 1 — Review config

The default runtime config is:

```text
config/default.toml
```

Important defaults:

- Proxy listener: `0.0.0.0:8080`
- Control gRPC: `0.0.0.0:9090`
- Control REST: `0.0.0.0:9091`
- Metrics: `0.0.0.0:9092`
- Policy service: `http://127.0.0.1:50052`
- Rules file: `config/rules.toml`

If you are running RL policy only, keep:

```toml
[pipeline]
ml_enabled = false
```

If you later enable the separate semantic ML classifier, point `[ml].endpoint` to that service, not to the RL policy port.

### Step 2 — Validate the config

```bash
cargo run -p nexus-gateway -- --config config/default.toml check
```

This verifies:

- gateway/control/metrics bind addresses
- TLS mode
- upstream definitions
- config schema validity

### Step 3 — Start supporting services

At minimum, start PostgreSQL and ensure the configured database is reachable.

To enable RL policy decisions and feedback ingestion, start the policy service from `nexus-ml`:

```bash
python ../nexus-ml/src/integration/policy_service.py \
  --checkpoint ../nexus-ml/checkpoints/best.pt \
  --port 50052 \
  --feedback-log ../nexus-ml/data/live/policy_events.jsonl \
  --online-train \
  --online-save ../nexus-ml/checkpoints/live-online.pt
```

### Step 4 — Start the gateway

```bash
cargo run -p nexus-gateway -- --config config/default.toml start
```

Useful companion commands:

```bash
cargo run -p nexus-gateway -- --config config/default.toml status
cargo run -p nexus-gateway -- --config config/default.toml token
```

### Step 5 — Verify the control plane

Health:

```bash
curl http://127.0.0.1:9091/api/health
```

Stats:

```bash
curl -H "Authorization: Bearer <ADMIN_TOKEN>" http://127.0.0.1:9091/api/stats
```

Policy service snapshot:

```bash
curl -H "Authorization: Bearer <ADMIN_TOKEN>" http://127.0.0.1:9091/api/policy
```

Manual RL replay updates:

```bash
curl -X POST http://127.0.0.1:9091/api/policy/train \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"gradient_updates\":25,\"replay_from_log_limit\":500}"
```

---

## Pipeline Order

The request path is intentionally layered from cheapest to most expensive:

1. `nexus-rate`
2. `nexus-lex`
3. `nexus-grammar`
4. `nexus-rules`
5. `nexus-anomaly`
6. `nexus-policy`
7. `nexus-ml-client` (only when enabled and not skipped)

This lets the gateway:

- block obvious attacks early
- route suspicious-but-uncertain traffic through deeper analysis
- feed final outcomes back to the RL policy agent

---

## Control Plane Endpoints

### Public

- `GET /api/health`

### Protected REST

- `GET /api/stats`
- `GET /api/logs`
- `GET /api/logs/:id`
- `GET /api/rules`
- `POST /api/rules`
- `POST /api/rules/synthesize`
- `GET /api/rules/versions`
- `GET /api/config`
- `GET /api/config/logs`
- `GET /api/policy`
- `GET /api/policy/events`
- `POST /api/policy/train`

### Runtime listeners

- Proxy traffic: `gateway.listen_addr`
- Control gRPC: `gateway.control_addr`
- Control REST: `gateway.rest_addr`
- Prometheus metrics: `gateway.metrics_addr`

---

## Configuration Highlights

### Core runtime

```toml
[gateway]
listen_addr = "0.0.0.0:8080"
rest_addr = "0.0.0.0:9091"
control_addr = "0.0.0.0:9090"
metrics_addr = "0.0.0.0:9092"
```

### RL policy integration

```toml
[policy]
enabled = true
endpoint = "http://127.0.0.1:50052"
feedback_enabled = true
feedback_batch_size = 64
feedback_flush_ms = 1000
```

### Optional semantic ML

```toml
[pipeline]
ml_enabled = false

[ml]
endpoint = "http://127.0.0.1:50053"
```

### GPS / Slack / TLS

```toml
[gps]
enabled = true

[slack]
enabled = false

[gateway.tls]
enabled = false
```

---

## Integration With Other Repositories

### `nexus-ml`

`nexus-core` calls the RL policy service over gRPC using `proto/policy.proto`:

1. `PolicyService.Decide` for action selection
2. `PolicyService.ReportEvents` for live feedback ingestion
3. `PolicyService.ListFeedbackEvents` for dashboard visibility
4. `PolicyService.TrainPolicy` for manual replay updates

### `nexus-dashboard`

The React dashboard consumes the protected REST control plane exposed by `nexus-control` and provides operator views for:

- dashboard metrics
- attack/config logs
- GPS rule synthesis
- policy status and JSONL tail
- manual RL training
- configuration visibility

---

## Notes

- `nexus-control` is a library crate embedded into the gateway runtime; you do not start it as a separate binary.
- Full workspace builds can fail if a running `nexus-gateway.exe` is still locking the existing binary on Windows. Stop the running process before rebuilding the whole workspace.
- `nexus-telemetry` and `nexus-metrics` are intentionally different:
  - `nexus-telemetry` keeps short in-memory policy/load signals
  - `nexus-metrics` exposes Prometheus-friendly runtime counters
