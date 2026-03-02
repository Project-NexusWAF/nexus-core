# nexus-rules

The rule engine for NexusWAF - evaluates HTTP requests against admin-defined security policies.

## Overview

This crate implements the semantic policy layer of the WAF, where human-written security rules are enforced. Each rule consists of:
- A **condition** (what to match)
- An **action** (what to do when matched)
- Metadata (priority, enabled status, description)

## Architecture

### Core Components

1. **Rule** (`src/rule.rs`)
   - Represents a single security rule
   - Loaded from TOML configuration
   - Contains condition and action

2. **Condition** (`src/condition.rs`)
   - Defines matching logic against requests
   - Supports path, method, IP, header, risk score, tags, regex
   - Composable with logical operators (AND, OR, NOT)
   - Includes custom CIDR matching for IPv4/IPv6

3. **RuleEngine** (`src/engine.rs`)
   - Evaluates rules against requests
   - Uses `parking_lot::RwLock` for thread-safe hot-reloading
   - Wrapped in `Arc` for shared ownership
   - Respects rule priority ordering

4. **RuleLayer** (`src/layer.rs`)
   - Implements `nexus_common::Layer` trait
   - Priority: 30 (after rate-limiting and lexical analysis)
   - Async-friendly evaluation

## Example Configuration

```toml
version = "1.0.0"

# Whitelist health checks
[[rules]]
id = "R001"
name = "Allow health checks"
enabled = true
priority = 5
action = "allow"
description = "Whitelist monitoring endpoints"

[rules.condition]
type = "path_exact"
value = "/health"

# Block external admin access
[[rules]]
id = "R002"
name = "Block external admin"
enabled = true
priority = 10
action = "block"
description = "Prevent admin access from non-private IPs"

[rules.condition]
type = "and"
conditions = [
    { type = "path_prefix", value = "/admin" },
    { type = "not", condition = { type = "ip_in_range", cidrs = ["10.0.0.0/8", "192.168.0.0/16"] } }
]

# Log SQL injection patterns
[[rules]]
id = "R003"
name = "Log SQLi patterns"
enabled = true
priority = 20
action = "log"

[rules.condition]
type = "regex_match"
target = "uri"
pattern = "(?i)(union.*select|drop.*table)"
```

## Condition Types

| Type | Fields | Description |
|------|--------|-------------|
| `path_prefix` | `value` | URI starts with prefix |
| `path_exact` | `value` | Path (no query) equals value |
| `method_is` | `methods` | HTTP method in list |
| `header_contains` | `header`, `value` | Header contains value (case-insensitive) |
| `ip_in_range` | `cidrs` | Client IP in CIDR range(s) |
| `risk_above` | `threshold` | Risk score > threshold |
| `has_tag` | `tag` | Request has threat tag |
| `and` | `conditions` | All sub-conditions match |
| `or` | `conditions` | Any sub-condition matches |
| `not` | `condition` | Sub-condition does NOT match |
| `regex_match` | `target`, `pattern` | Regex matches target field |

### Regex Match Targets
- `"uri"` - Full request URI
- `"body"` - Request body (if UTF-8)
- `"header:X"` - Specific header (e.g., "header:user-agent")

## Actions

- **Block**: Return 403 Forbidden, stop pipeline processing
- **Allow**: Whitelist request, skip remaining rules (early return)
- **Log**: Emit warning log, tag request, continue evaluation

## Usage

```rust
use nexus_rules::{RuleEngine, RuleLayer, RuleSet};
use nexus_common::Layer;

// Load rules from file
let ruleset = RuleSet::from_file("config/rules.toml")?;

// Create engine
let engine = RuleEngine::new(ruleset);

// Wrap in layer for pipeline integration
let layer = RuleLayer::new(engine.clone());

// Evaluate request
let decision = layer.analyse(&mut ctx).await?;

// Hot-reload rules
engine.reload_from_file("config/rules.toml")?;
```

## Design Decisions

### Why RwLock over Mutex?
- **Read-heavy workload**: Rule evaluation (reads) happens on every request, while reloads (writes) are rare
- **parking_lot::RwLock**: More efficient than std with no poisoning, fair scheduling
- **Performance**: Multiple concurrent readers without blocking

### Why Arc wrapping?
- **Shared ownership**: Control plane and multiple request handlers need access
- **Thread-safe**: Safe to share across async tasks and threads
- **Hot-reload**: Allows atomic ruleset replacement without recreating engine

### CIDR Implementation
- Custom implementation for both IPv4 and IPv6
- Bitwise mask operations for efficient matching
- Handles edge cases (0.0.0.0/0, ::/0, invalid CIDRs)
- No external dependencies beyond std

### Regex Caching
- Thread-local cache per pattern string
- Avoids recompilation on repeated evaluations
- Trade-off: Memory vs CPU for pattern-heavy rules
- Falls back gracefully on invalid regex

## Testing

Comprehensive test coverage includes:
- ✅ All condition variants with positive/negative cases
- ✅ Logical nesting (AND, OR, NOT combinations)
- ✅ IPv4 and IPv6 CIDR matching
- ✅ Rule priority ordering
- ✅ Action semantics (block, allow, log)
- ✅ Disabled rule filtering
- ✅ Hot-reload functionality
- ✅ Integration tests with realistic scenarios
- ✅ Regex performance and caching

Run tests:
```bash
cargo test -p nexus-rules
```

## Dependencies

- `nexus-common`: Shared types (RequestContext, Decision, Layer trait)
- `nexus-config`: Configuration loading (when implemented)
- `serde`, `toml`: TOML deserialization
- `parking_lot`: High-performance RwLock
- `regex`: Pattern matching
- `async-trait`: Async trait support
- `tracing`: Structured logging

## Future Enhancements

- Rate-limit specific rules (e.g., max 100 blocks/min)
- Rule statistics and metrics
- Dynamic rule updates via gRPC control plane
- Rule validation on load (detect conflicts, unreachable rules)
- Performance profiling per rule
- Geo-IP based conditions
