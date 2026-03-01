# Filtered Session D-Bus Access Plan

## Problem

We need sandboxed processes to use session D-Bus in a **generic** way (including but not limited to `notify-send`) without exposing full host session bus access.

Directly bind-mounting the host session bus socket is unacceptable because it grants broad access to host session services (for example, keyring APIs) and violates the intended explicit-boundary model.

## Goals

1. Enable sandboxed D-Bus clients through a constrained boundary.
2. Keep default behavior unchanged when feature is not configured.
3. Preserve default-deny security semantics with explicit allowlists.
4. Keep implementation auditable and fail-closed.

## Non-goals

1. Full transparent session bus parity for all clients/services.
2. Implicit broad access to host session services.
3. Supporting D-Bus without explicit policy rules in config.

## Proposed Architecture

Use `xdg-dbus-proxy` as a policy enforcement boundary between sandbox and host session bus.

### Runtime flow

1. Config is parsed and validated, including new `dbus` rule section.
2. If dbus rules exist:
   - resolve host `DBUS_SESSION_BUS_ADDRESS`
   - start `xdg-dbus-proxy` with allowlist arguments derived from config
   - create proxy output socket in an execave-owned temp dir
3. Sandbox setup:
   - bind-mount proxy output socket into sandbox at fixed path (for example `/tmp/execave-dbus.sock`)
   - set sandbox env `DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/execave-dbus.sock`
4. Sandboxed process talks to proxy socket; proxy forwards only policy-allowed traffic.
5. On shutdown, proxy process is terminated and socket/tempdir are cleaned up.

### Security properties

1. No direct host bus socket mount.
2. Allowlist-only traffic.
3. Fail-closed when proxy is unavailable or exits.
4. Keyring and other sensitive services remain inaccessible unless explicitly granted.

## Config Model (proposed)

Add a top-level `dbus` section in TOML:

```toml
dbus = [
  "talk:org.freedesktop.Notifications",
  "see:org.freedesktop.Notifications",
  # optional finer-grained rules if needed:
  # "call:org.freedesktop.Notifications:org.freedesktop.Notifications:Notify",
]
```

Rule types (exact final syntax to match codebase conventions):

1. `talk:<name>`: allow method calls to destination bus name.
2. `own:<name>`: allow owning a bus name.
3. `see:<name>`: allow visibility of a bus name.
4. Optional fine-grained method/signal rules if required by workloads.

Validation requirements:

1. Reject malformed bus names/rule syntax.
2. Reject duplicates/conflicting combinations where policy intent is ambiguous.
3. Keep deterministic rule ordering for reproducible proxy argument generation.
4. Return rich operation-context errors (operation -> context -> wrapped error).

## Code-level Implementation Plan

### 1) New `internal/dbusrules` package

Responsibilities:

1. Parse dbus rule strings.
2. Validate rule format and cross-rule constraints.
3. Produce canonical rule structures.
4. Render deterministic proxy-argument fragments (or intermediate policy model).

Primary files (new):

1. `internal/dbusrules/dbusrules.go` (types + parser entrypoints)
2. `internal/dbusrules/validate.go` (cross-rule validation)
3. `internal/dbusrules/args.go` (policy to proxy argument mapping)
4. `internal/dbusrules/*_test.go` and fuzz tests

### 2) Extend config parsing

Files:

1. `internal/config/config.go`
2. parser/validation tests in `internal/config/*test.go`

Changes:

1. Add `DBusRules` field to `config.Config`.
2. Extend TOML raw struct with `DBus []string 'toml:"dbus"'`.
3. Route `dbus` entries through parser/validator.
4. Preserve behavior for existing configs with no `dbus` section.

### 3) New `internal/dbusproxy` package

Responsibilities:

1. Resolve and validate `xdg-dbus-proxy` binary path/safety (reuse binary validation pattern where applicable).
2. Start proxy process with generated allowlist arguments.
3. Manage lifecycle (start, readiness, stop, cleanup).
4. Expose proxy socket path for sandbox wiring.

Primary files (new):

1. `internal/dbusproxy/dbusproxy.go`
2. `internal/dbusproxy/process.go`
3. `internal/dbusproxy/*_test.go`

Behavior requirements:

1. Explicit errors when `DBUS_SESSION_BUS_ADDRESS` is absent.
2. Explicit errors when proxy binary is unavailable.
3. No fallback to host session socket mount.

### 4) Runtime wiring in CLI startup

Files:

1. `cmd/execave/main.go`

Changes:

1. Extend networking/setup orchestration to also initialize dbus proxy when dbus rules exist.
2. Return proxy cleanup closure similar to existing proxy lifecycle management.
3. Pass dbus runtime paths into sandbox construction.

### 5) Sandbox plumbing

Files:

1. `internal/sandbox/sandbox.go`
2. `internal/sandbox/*test.go`
3. `internal/sandbox/integration_test.go`

Changes:

1. Extend runtime path struct(s) to carry dbus proxy socket path.
2. Add bwrap bind mount for proxy socket.
3. Add bwrap env injection (`--setenv DBUS_SESSION_BUS_ADDRESS ...`) only when dbus proxy is enabled.
4. Preserve ordering and behavior of existing mounts/tunnel setup.

### 6) Documentation updates

Files:

1. `README.md`
2. `docs/architecture.md`
3. `docs/security-model.md`
4. `openspec/config.yaml` (context/rules updates per project requirement)

Updates:

1. New feature overview, config examples, and dependency requirements.
2. Security guarantees/limitations for filtered D-Bus.
3. Explicit statement that full session bus exposure is not performed.

## Testing Plan

### Unit tests

1. `dbusrules` parser: valid/invalid grammar, duplicate detection, conflict checks.
2. `dbusrules` mapping: deterministic proxy args from canonical rules.
3. `dbusproxy` command construction and lifecycle error handling.
4. `sandbox` args: mount/env injection for dbus enabled/disabled.

### Integration tests

1. Startup failure paths:
   - missing `DBUS_SESSION_BUS_ADDRESS`
   - missing `xdg-dbus-proxy`
2. Successful wiring path using a fake proxy binary that records received args and creates a socket marker.
3. Coexistence with existing net proxy/tunnel path.

### E2E direction

1. Add a scenario where sandbox command performs a D-Bus call allowed by policy and succeeds.
2. Add a denied D-Bus scenario and verify fail-closed behavior.

## Rollout / Compatibility

1. Feature is opt-in via config; current users unaffected.
2. If users configure `dbus` rules but host lacks `xdg-dbus-proxy`, startup fails with actionable error.
3. Existing `fs`, `net`, `syscall` behavior remains unchanged.

## Risks and Mitigations

1. **Risk:** Incorrect rule-to-flag mapping over-permits access.  
   **Mitigation:** strict parser + deterministic mapping tests + security doc review.

2. **Risk:** Proxy lifecycle leaks process/socket resources.  
   **Mitigation:** explicit stop/cleanup paths and integration tests for shutdown.

3. **Risk:** Feature interaction with network tunnel or monitor paths.  
   **Mitigation:** integration tests covering combined modes.

4. **Risk:** Users expect full bus behavior and hit denied calls.  
   **Mitigation:** clear docs and examples for expanding allowlists intentionally.
