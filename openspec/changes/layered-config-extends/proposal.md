## Why

Teams need to share baseline sandbox rules across multiple projects and agents without copying large rule sets into every `execave.toml`. Adding layered config composition now reduces drift, keeps policy auditable, and preserves default-deny behavior by reusing the existing validation model.

## What Changes

- Add `extends = ["<path>", ...]` to config files to compose rules from other config files.
- Path handling for `extends` entries matches fs path rules:
  - absolute paths are used as-is
  - relative paths resolve against the directory of the file that declares `extends`
  - `~` expands to the current user's home directory
- Load extended configs recursively with cycle detection.
- Validate each config file independently using the current single-file validation pipeline before merge.
- Merge by union of rules from all loaded files; remove only exact duplicate rules.
- Run the existing full validation pipeline again on the merged union (same checks as a single config).
- Include rule source file paths in merge/final-validation conflict errors so users can locate conflicting rules across layers.
- Preserve config-file protection semantics across layered configs by carrying per-file config protection through merged validation/runtime behavior.
- **BREAKING**: none (configs without `extends` continue to work unchanged).

## Playbooks

### New Playbooks
<!-- none -->

### Modified Playbooks
- `configuring-execave`: Add use cases for composing config via `extends`, path resolution (`absolute`, `relative`, `~`), cycle errors, and cross-file conflict errors with source file reporting.
- `iterating-config`: Add use cases for editing layered configs and troubleshooting errors that point to multiple source files.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `config`: Extend config format and load semantics with recursive `extends`, per-file path resolution, per-file pre-validation, union merge with exact-dedup, post-merge full validation, cycle detection, and source-aware error reporting.

## Impact

- `internal/config`: config parsing/loading flow changes to support recursive `extends`, path normalization, cycle detection, merge, and source-aware diagnostics.
- `internal/fsrules` and `internal/netrules` validation call sites: error messages and/or rule metadata wiring updated to include originating config file context in conflicts.
- `internal/sandbox`: config-protection behavior reviewed/aligned so layered configs keep forced read-only guarantees.
- Tests: unit/integration/e2e updates for layered load order independence, duplicate dedup semantics, cross-file conflicts, cycle detection, and source-aware errors.
- Documentation: `README.md`, `docs/architecture.md`, `docs/security-model.md`, and config examples updated for layered config behavior.
- Security impact: touches config parsing and validation surface only; no intended change to sandbox boundary, bwrap namespace isolation, or allow/deny rule resolution semantics. Trust boundaries remain config file input (trusted by user), execave validation, and untrusted child process; stricter diagnostics reduce misconfiguration risk.
