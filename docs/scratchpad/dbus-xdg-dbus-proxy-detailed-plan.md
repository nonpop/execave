# D-Bus via xdg-dbus-proxy: Detailed Implementation Plan

## Purpose

Implement **opt-in, filtered session D-Bus access** for sandboxed commands using `xdg-dbus-proxy`, while preserving Execave's default-deny and fail-closed security posture.

This document is a planning artifact only. It defines scope, security requirements, concrete tasks, and verification criteria before implementation.

## Current State

- Execave currently enforces:
  - Filesystem policy (`fs` rules) via bwrap mounts
  - Network policy (`net` rules) via internal HTTP proxy/tunnel
  - Syscall policy (`syscall` rules) via seccomp deny-list
- D-Bus policy is **not implemented** yet.

## Problem Statement

Sandboxed processes need limited access to host session D-Bus services (e.g., notifications) without exposing the host session bus socket directly.

Directly mounting the host bus socket violates explicit-boundary design and can expose sensitive services (e.g., keyring APIs).

## Goals

1. Add opt-in D-Bus support through a filtered boundary.
2. Keep behavior unchanged when no D-Bus rules are configured.
3. Preserve default-deny semantics with explicit allowlists.
4. Fail closed when prerequisites are missing or proxy startup fails.
5. Keep implementation auditable and deterministic.
6. Follow existing error-handling and testing conventions.

## Non-Goals

1. Full transparent parity with unrestricted session bus behavior.
2. Implicit broad D-Bus access.
3. Supporting D-Bus access without explicit config rules.
4. Replacing existing network proxy or filesystem enforcement.

## Security Invariants (Must Hold)

1. **No direct host session bus socket mount** into sandbox.
2. All sandbox D-Bus traffic goes through `xdg-dbus-proxy` when D-Bus is enabled.
3. D-Bus feature is **disabled by default**.
4. Startup errors are explicit and fail execution (no fallback to unsafe mode).
5. D-Bus log visibility rules (if added) are display-only and never alter enforcement.
6. No regression to existing `fs`, `net`, `syscall` boundaries.

## Proposed User Config Model

### New top-level section

```toml
dbus = [
  "talk:org.freedesktop.Notifications",
  "see:org.freedesktop.Notifications",
  "call:org.freedesktop.Notifications:org.freedesktop.Notifications.Notify@/org/freedesktop/Notifications",
]
```

### Rule grammar (planned)

- Basic policy:
  - `see:<name>`
  - `talk:<name>`
  - `own:<name>`
- Fine-grained policy:
  - `call:<name>:<rule>`
  - `broadcast:<name>:<rule>`

### Validation requirements

1. Reject malformed actions/syntax.
2. Reject invalid bus names and invalid filter format.
3. Reject exact duplicate rules.
4. Deterministic canonicalization and argument generation.
5. Report errors with operation/context chain.

## Runtime Architecture

When `dbus` rules exist:

1. Resolve host `DBUS_SESSION_BUS_ADDRESS`.
2. Resolve and validate `xdg-dbus-proxy` binary (same binary-safety model as bwrap/strace).
3. Create execave-owned temp directory.
4. Start `xdg-dbus-proxy` with:
   - host session bus address (input)
   - proxy socket path (output)
   - `--filter`
   - generated policy flags from config
5. Wait for readiness via `--fd` handshake.
6. Pass proxy socket path into sandbox runtime paths.
7. In sandbox bwrap args:
   - bind-mount proxy socket at fixed in-sandbox path
   - set `DBUS_SESSION_BUS_ADDRESS=unix:path=<sandbox-proxy-path>`
8. On shutdown:
   - stop proxy process
   - remove temp dir/socket

## No-Sandbox Mode Behavior (Planning Decision)

`--no-sandbox` is diagnostic mode and should remain explicit about reduced guarantees.

Planned behavior:

1. If D-Bus rules are configured with `--no-sandbox`, still start `xdg-dbus-proxy`.
2. Inject `DBUS_SESSION_BUS_ADDRESS` into traced process environment to use proxy.
3. Document that host-level bypass remains possible in no-sandbox mode (not a boundary).

## Logging Strategy (Planned)

### Enforcement logs

- D-Bus operations should appear in access log as a new operation type (e.g., `DBUS`) if implementation can reliably classify attempts/results from proxy events.
- Minimum acceptable first pass:
  - rely on `xdg-dbus-proxy --log` output integration with structured mapping into `accesslog.Entry`.
  - if structured mapping is not robust, explicitly defer D-Bus entries to phase 2 and document limitation.

### Visibility rules

Phase 1 recommendation:

- Do **not** add dbus log-visibility rules yet.
- Reuse existing filtering behavior for fs/net/syscall unchanged.
- Add dbus `nolog` only in a follow-up once format is stable.

## Detailed Work Plan

## Phase 0: Design Lock (No Code)

1. Finalize rule grammar and duplicate policy.
2. Finalize no-sandbox semantics.
3. Finalize logging scope for phase 1.
4. Capture decisions in:
   - `openspec` proposal/design/tasks updates
   - `docs/security-model.md` trust-boundary delta

Exit criteria:

- Grammar and semantics approved with concrete examples.

## Phase 1: `internal/dbusrules` Package

Files:

- `internal/dbusrules/dbusrules.go`
- `internal/dbusrules/validate.go` (optional split)
- `internal/dbusrules/args.go` (optional split)
- `internal/dbusrules/*_test.go`

Tasks:

1. Define rule/action types and canonical rule struct.
2. Parse single rule and list of rules.
3. Validate names/filter syntax and duplicates.
4. Collapse `see/talk/own` precedence per name.
5. Generate deterministic `xdg-dbus-proxy` args.

Security notes:

- Over-permissive arg generation is a boundary bug; tests must include precedence and conflicting-rule cases.

Exit criteria:

- Unit + fuzz tests pass for parser/validator/args determinism.

## Phase 2: Config Integration

Files:

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/integration_test.go`

Tasks:

1. Add `DBusRules` typed field to `config.Config`.
2. Extend TOML parsing with `dbus = []`.
3. Route dbus rule bodies to `dbusrules` parser.
4. Preserve current behavior when section is absent.

Security notes:

- Config parse path is boundary-critical; must fail on malformed dbus rules.

Exit criteria:

- Parse/load tests cover valid/invalid dbus scenarios.

## Phase 3: `internal/dbusproxy` Package

Files:

- `internal/dbusproxy/dbusproxy.go`
- `internal/dbusproxy/process.go` (optional split)
- `internal/dbusproxy/*_test.go`

Tasks:

1. Resolve/validate `xdg-dbus-proxy` binary safely.
2. Resolve host session bus address from environment.
3. Create temp dir and socket path.
4. Build command args (`--fd`, `--filter`, rule flags).
5. Start process, wait for readiness signal.
6. Expose `Stop()` + cleanup semantics.
7. Hard fail if prerequisites missing.

Security notes:

- No fallback to host bus socket mount.
- Treat missing env/binary/readiness failure as startup error.

Exit criteria:

- Unit/integration tests for success and fail-closed paths.

## Phase 4: Sandbox Plumbing

Files:

- `internal/sandbox/sandbox.go`
- `internal/sandbox/sandbox_test.go`
- `internal/sandbox/integration_test.go`

Tasks:

1. Extend runtime path struct to carry optional D-Bus socket path.
2. Add bwrap `--ro-bind` for D-Bus proxy socket.
3. Add bwrap `--setenv DBUS_SESSION_BUS_ADDRESS ...` only when enabled.
4. Keep mount/order logic deterministic and non-regressing.

Security notes:

- Wrong mount/env wiring can silently disable filtering or break apps.
- Must panic-check internal impossible states where appropriate.

Exit criteria:

- Argument-construction tests prove expected bind/env presence/absence.

## Phase 5: CLI Orchestration

Files:

- `cmd/execave/main.go`

Tasks:

1. Extend setup orchestration to initialize/cleanup dbus proxy alongside existing network proxy setup.
2. Pass dbus runtime path into sandbox and monitored runner paths.
3. Ensure deferred cleanup ordering is robust under errors/signals.

Security notes:

- Startup sequence must be fail-closed: any dbus proxy setup failure aborts run.

Exit criteria:

- Integration tests for startup with and without dbus rules.

## Phase 6: Monitoring/Logging (if in scope for phase 1)

Files (tentative):

- `internal/accesslog/accesslog.go`
- `internal/textlog/writer.go`
- `internal/logfilter/*` (only if dbus nolog introduced)
- `internal/dbusproxy/*` for log emission

Tasks:

1. Decide DBUS entry shape and classification.
2. Emit entries with stable rule attribution.
3. Extend text-log formatting and tests.

Exit criteria:

- Deterministic output and filtering behavior documented/tested.

## Phase 7: Spec + Docs Sync

Files:

- `README.md`
- `docs/architecture.md`
- `docs/security-model.md`
- `openspec/config.yaml`
- `openspec/specs/config/spec.md` (and any impacted specs/playbooks)

Tasks:

1. Document dependency on `xdg-dbus-proxy`.
2. Document new `dbus` config syntax with safe examples.
3. Add security guarantees and limitations.
4. Update openspec context/rules to include new package and trust boundary.

Exit criteria:

- Docs/specs consistent with implemented behavior.

## Test Plan (Detailed)

## Unit Tests

1. dbusrules parser:
   - valid basic/fine-grained rules
   - invalid actions/name/filter syntax
2. dbusrules validator:
   - duplicate detection
   - precedence collapsing semantics
3. dbusrules arg generation:
   - deterministic ordering
   - correct `--see/--talk/--own/--call/--broadcast` mapping
4. dbusproxy lifecycle:
   - command construction
   - readiness wait
   - stop/cleanup paths
5. sandbox args:
   - dbus bind/env present only when configured

## Fuzz Tests

1. dbusrules parser fuzz target for malformed/edge inputs.
2. filter/name/path grammar fuzz target for robustness.

## Integration Tests

1. Missing `DBUS_SESSION_BUS_ADDRESS` => startup error.
2. Missing `xdg-dbus-proxy` => startup error.
3. Fake proxy binary receives expected args and readiness handshake.
4. Coexistence with existing network proxy path.

## E2E Tests

1. Allowed D-Bus call succeeds with explicit rule.
2. Denied D-Bus call fails without matching rule.
3. Feature-disabled run behaves exactly as before.
4. Combined scenario with fs/net/syscall + dbus rules.

## Security Review Checklist

Before merge, explicitly review:

1. Bypass paths that could expose host bus directly.
2. Rule translation mismatches that over-permit.
3. Process cleanup/resource leaks causing stale sockets.
4. No-sandbox behavior documentation clarity.
5. Error messages include operation/context/wrapped cause.

## Failure Modes and Expected Behavior

1. Config has dbus rules, but env missing:
   - fail before sandbox starts.
2. Binary not found/unsafe:
   - fail before sandbox starts.
3. Proxy start/readiness timeout:
   - fail before sandbox starts.
4. Proxy exits during run:
   - D-Bus calls fail closed.
5. Cleanup errors:
   - report to stderr, do not mask primary run error.

## Risks and Mitigations

1. **Risk:** Incorrect rule-to-flag mapping over-permits access.
   **Mitigation:** strict parser + deterministic mapping tests + security doc review.

2. **Risk:** Proxy lifecycle leaks process/socket resources.
   **Mitigation:** explicit stop/cleanup paths and integration tests for shutdown.

3. **Risk:** Feature interaction with network tunnel or monitor paths.
   **Mitigation:** integration tests covering combined modes.

4. **Risk:** Users expect full bus behavior and hit denied calls.
   **Mitigation:** clear docs and examples for expanding allowlists intentionally.

## Rollout Plan

1. Land parser + tests first.
2. Land proxy lifecycle package + integration tests.
3. Land sandbox/CLI wiring.
4. Land docs/spec updates.
5. Optional: land structured DBUS access-log integration as separate follow-up if needed.

## Open Questions (Resolve Before Coding)

1. Do we require DBUS logs in phase 1, or defer to phase 2?
2. Should dbus nolog be included now or delayed?
3. Exact behavior in `--no-sandbox` mode when dbus rules exist.
4. Should wildcard name patterns be allowed in all actions uniformly?
5. Readiness timeout policy and user-facing error wording.

## Definition of Done

1. All new unit/integration/e2e tests pass.
2. Existing test suite passes without regressions.
3. Security invariants above are demonstrably satisfied.
4. Docs + openspec + README are synchronized.
5. Default behavior unchanged for configs without `dbus`.
