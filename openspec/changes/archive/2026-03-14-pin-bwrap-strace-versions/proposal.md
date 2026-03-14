## Why

execave relies on bwrap and strace as external binaries whose behavior is security-critical: bwrap enforces the sandbox boundary and strace parses filesystem access via a regex-matched output format. Any version mismatch that silently changes behavior could weaken isolation or corrupt the access log without warning. Currently no version validation is performed.

## What Changes

- At startup, execave runs `bwrap --version` and `strace --version` and compares the installed versions against pinned known-good versions (bwrap 0.11.0, strace 6.18).
- Three compatibility tiers: **OK** (known compatible, no warning), **WARN** (probably compatible, print warning to stderr but continue), **ERROR** (incompatible, print error and exit).
- Tier thresholds based on versioning research:
  - bwrap: same 0.11.x minor → OK; higher minor within 0.x (0.12+) → WARN; older or major bump (≥1.0.0) → ERROR
  - strace: exact 6.18 → OK; higher minor within 6.x (6.19+) → WARN; older or major bump (≥7.0) → ERROR
- Version check runs after binary path resolution and ownership validation, before any sandbox or monitor operation.

## Playbooks

### New Playbooks
*(none)*

### Modified Playbooks
- `configuring-execave`: New use cases for the startup version check — incompatible version blocks execution, compatible-but-newer version prints a warning.

## Capabilities

### New Capabilities
*(none)*

### Modified Capabilities
- `sandbox`: Version check functions `CheckBwrapVersion` and `CheckStraceVersion` added alongside the existing `ResolveBwrap`/`ResolveStrace`/`ValidateBinary` functions; `Sandbox.Run` extended to enforce bwrap version compatibility.

## Impact

- **Code**: New `internal/sandbox/versions.go`; integration in `sandbox.Run()`, `runner.buildSandboxedMonitor()`, `runner.runMonitored()`.
- **Security**: Adds a defense-in-depth check at the sandbox boundary. Does not change permission logic, rule resolution, or bwrap arguments. The check protects against silently running with an untested bwrap/strace that could weaken isolation.
- **Trust boundaries**: Reads output from bwrap and strace binaries (already validated for root ownership). Version string is parsed, not executed.
- **Compatibility**: No config format changes. No behavioral changes for users on pinned versions.
