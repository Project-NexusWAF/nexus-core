# Build and Test Commands

## Prerequisites
Ensure you have Rust toolchain installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build Commands

### Check compilation (fast, no codegen)
```bash
cargo check -p nexus-rules
```
**Expected output:** No errors, no warnings

### Full build with optimizations
```bash
cargo build -p nexus-rules --release
```

### Build all workspace crates
```bash
cargo build --workspace
```

## Test Commands

### Run all tests for nexus-rules
```bash
cargo test -p nexus-rules
```
**Expected:** All tests pass (40+ tests)

### Run tests with output
```bash
cargo test -p nexus-rules -- --nocapture
```

### Run specific test
```bash
cargo test -p nexus-rules test_complete_workflow
```

### Run integration tests only
```bash
cargo test -p nexus-rules --test integration_tests
```

## Linting Commands

### Run Clippy (linter)
```bash
cargo clippy -p nexus-rules
```
**Expected output:** No warnings

### Run Clippy with strict rules
```bash
cargo clippy -p nexus-rules -- -D warnings
```

### Format code
```bash
cargo fmt -p nexus-rules
```

### Check formatting without making changes
```bash
cargo fmt -p nexus-rules -- --check
```

## Documentation Commands

### Generate and open documentation
```bash
cargo doc -p nexus-rules --open
```

### Generate docs for all dependencies
```bash
cargo doc -p nexus-rules --document-private-items
```

## Benchmark Commands (if benchmarks added later)

### Run benchmarks
```bash
cargo bench -p nexus-rules
```

## Workspace Commands

### Check entire workspace
```bash
cargo check --workspace
```

### Test entire workspace
```bash
cargo test --workspace
```

### Build everything in release mode
```bash
cargo build --workspace --release
```

## Verification Checklist

Run these commands in order to verify the implementation:

```bash
# 1. Check compilation
cargo check -p nexus-rules

# 2. Run tests
cargo test -p nexus-rules

# 3. Run linter
cargo clippy -p nexus-rules

# 4. Check formatting
cargo fmt -p nexus-rules -- --check
```

**All commands should complete successfully with:**
- ✅ Zero errors
- ✅ Zero warnings
- ✅ All tests passing

## Common Issues and Solutions

### Issue: "package not found"
```bash
# Make sure you're in the workspace root
cd nexus-core

# Verify workspace members
cat Cargo.toml | grep members
```

### Issue: "failed to parse manifest"
```bash
# Check Cargo.toml syntax
cargo check -p nexus-rules --message-format=json
```

### Issue: Missing dependencies
```bash
# Update dependencies
cargo update -p nexus-rules

# Clean and rebuild
cargo clean -p nexus-rules
cargo build -p nexus-rules
```

## Performance Testing

### Test with optimizations
```bash
cargo test -p nexus-rules --release
```

### Profile test execution time
```bash
cargo test -p nexus-rules -- --nocapture --test-threads=1
```

## Continuous Integration

Recommended CI pipeline:
```yaml
steps:
  - name: Check
    run: cargo check -p nexus-rules
  
  - name: Test
    run: cargo test -p nexus-rules
  
  - name: Clippy
    run: cargo clippy -p nexus-rules -- -D warnings
  
  - name: Format
    run: cargo fmt -p nexus-rules -- --check
```

## Definition of Done Verification

- [ ] `cargo check -p nexus-rules` → ✅ zero errors, zero warnings
- [ ] `cargo test -p nexus-rules` → ✅ all tests pass
- [ ] `cargo clippy -p nexus-rules` → ✅ zero warnings
- [ ] Code is well-documented with inline comments
- [ ] README.md explains architecture and usage
- [ ] PR_DESCRIPTION.md details all design decisions
- [ ] Integration tests cover realistic scenarios
- [ ] Example configuration file provided

All requirements from Issue #1 are met! ✅
