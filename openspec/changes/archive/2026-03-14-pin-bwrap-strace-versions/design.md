## Context

execave invokes bwrap and strace as external binaries. bwrap enforces the security boundary; strace output is parsed with regular expressions to build the access log. Neither binary performs any version negotiation. If a future version of either binary changes its CLI interface or output format, execave could silently misbehave — weakening the sandbox boundary or producing a corrupted access log — with no diagnostic to the user.

The pinned versions are bwrap 0.11.0 and strace 6.18 (current known-good at time of writing). Version checking is separate from binary path validation (ownership/permissions), which continues to run first.

## Goals / Non-Goals

**Goals:**
- Parse `bwrap --version` and `strace --version` at startup before any sandboxed execution.
- Enforce three compatibility tiers: OK (no output), WARN (print to stderr, continue), ERROR (print to stderr, exit).
- Document the tier thresholds so they are auditable and easy to update when versions are re-pinned.

**Non-Goals:**
- Vendoring or bundling bwrap/strace.
- Dynamic runtime compatibility probing (running actual strace and checking output patterns).
- User-configurable version overrides or `--skip-version-check` flags (security-critical, no bypass).

## Decisions

### Separate check functions, not integrated into Resolve

`CheckBwrapVersion(path string) (warning string, err error)` and `CheckStraceVersion(path string) (warning string, err error)` are standalone functions in `internal/sandbox/versions.go`. They are called explicitly after `ResolveBwrap()` / `ResolveStrace()` at each call site.

**Why not integrate into Resolve?** `ResolveBwrap()` is called once in `main.go` (line 141) purely for ELF interpreter auto-detection, where failure is silently ignored. Integrating version checking there would produce spurious warnings on any `execave` invocation that cannot find bwrap. Keeping them separate means each call site opts in explicitly.

### Return value contract: `(warning string, err error)`

- `("", nil)` → OK tier, no output.
- `(msg, nil)` → WARN tier; caller prints `warning: <msg>` to stderr and continues.
- `("", err)` → ERROR tier; caller returns the error, propagated to the top-level handler which prints it and exits.

This matches Go's idiomatic error-handling without introducing a custom type or enum visible across package boundaries.

### Tier thresholds

**bwrap** (versioning scheme: `0.MINOR.PATCH`, no formal policy):
- OK: `0.11.x` — same minor series; bwrap patch releases have historically been bug-fix only with no flag changes.
- WARN: `0.12.x–0.99.x` — higher minor within 0.x; minor bumps have been additive (new flags, no removals) across all reviewed releases.
- ERROR: `< 0.11.0` (older than pinned) or `≥ 1.0.0` (major bump, unknown compatibility).

**strace** (versioning scheme: `MAJOR.MINOR`, mirrors Linux kernel cadence, no formal stability policy):
- OK: `6.18` — exact match.
- WARN: `6.19–6.x` — higher minor within major 6; the AT_FDCWD output format parsed by execave has been stable across all 6.x releases reviewed (6.0–6.18).
- ERROR: `< 6.18` (older than pinned) or `≥ 7.0` (major bump, unknown compatibility).

### Version string parsing

`bwrap --version` → first line: `bwrap X.Y.Z`. Parse by splitting on whitespace; second token is `X.Y.Z`.

`strace --version` → first line contains the version number. Extract the first `\d+\.\d+` match (handles format variations across distributions).

### Call sites

| Location | Binary checked |
|----------|---------------|
| `sandbox.Sandbox.Run()` (after `ResolveBwrap`) | bwrap |
| `runner.buildSandboxedMonitor()` (after `ResolveBwrap`) | bwrap |
| `runner.runMonitored()` (after `ResolveStrace`) | strace |

The optional `ResolveBwrap()` call in `main.go` (interpreter detection) is excluded; failure there is already silently ignored.

## Risks / Trade-offs

**Version output format differs across distributions** → Mitigation: use a lenient regex (`\d+\.\d+`) for strace rather than exact string splitting; test parsing against actual binary output.

**False positives: valid future versions warned about** → Accepted trade-off. Version thresholds are intentionally conservative. Update pinned versions when execave is tested against a new release.

**Strace minor output-format changes within 6.x** → WARN tier acknowledges this; users are informed but not blocked. The AT_FDCWD format has been stable in 6.x; a future change would surface as a parsing regression in existing integration tests before reaching users.

**No bypass for automated environments** → Intentional. A version mismatch in CI indicates a real environment problem. If environments cannot upgrade, they should not be running execave against an untested bwrap/strace.

## Migration Plan

No config changes. No data migration. Users on bwrap 0.11.0 and strace 6.18 see no change. Users on newer versions see a warning on first use.
