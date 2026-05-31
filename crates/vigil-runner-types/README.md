# vigil-runner-types

[![crates.io](https://img.shields.io/crates/v/vigil-runner-types.svg)](https://crates.io/crates/vigil-runner-types)
[![docs.rs](https://docs.rs/vigil-runner-types/badge.svg)](https://docs.rs/vigil-runner-types)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Pure types + env policy for [Vigil](https://vigils.ai)'s sandbox runner** — `ExecutionPlan`, `SandboxProfile`, `RunnerError`, `RunnerAuditSink`, `apply_native_env_policy`.

Extracted from `vigil-runner` for crates.io publish (ADR 0018). 0 vigil deps + 0 wasmtime/sandbox-linux deps — pure types & env-policy filter.

## What's in

- `ExecutionPlan` / `RunnerKind` / `RunnerSpecific` / `SandboxProfile` / `ExecutionResult` — execution descriptors
- `RunnerError` / `RejectField` — typed errors
- `NullAuditSink` / `RunnerAuditSink` trait / `RunnerEvent` — audit contract
- `apply_native_env_policy` + `RESERVED_SYSTEM_ENV_KEYS` + `is_reserved_env_key` — env policy filter (ADR 0007 §I-7.1)
- `ScrubCallback` type alias — runner scrub callback type

## What's NOT in

- `WasmRunner` (wasmtime impl) — stays in `vigil-runner`
- `spawn_native` (tokio + Landlock impl) — stays in `vigil-runner`
- `default_scrub` (uses `vigil-redaction::scrub_text`) — stays in `vigil-runner`
- `leak_scan` (uses `vigil-redaction::scan_hard_findings`) — stays in `vigil-runner`

## Usage

```toml
[dependencies]
vigil-runner-types = "0.12"
```

```rust
use vigil_runner_types::{SandboxProfile, RunnerKind, RunnerSpecific, apply_native_env_policy};

// Build sandbox profile
let profile = SandboxProfile {
    read_dirs: vec!["/tmp/safe".into()],
    write_dirs: vec![],
    // ...
};

// Apply env policy to a Command (atomic env_clear + system env + user_env)
let mut cmd = std::process::Command::new("/bin/sh");
apply_native_env_policy(&mut cmd, [("API_KEY", "<value>")]);
```

## Invariants

ADR 0007 § 5 sandbox invariants I-7.1 ~ I-7.9 全保留(types 此处,impl 在 `vigil-runner` 主 crate)。

## License

Apache-2.0 © Vigil Project Contributors
