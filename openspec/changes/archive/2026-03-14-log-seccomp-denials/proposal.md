## Why

The seccomp BPF filter blocks ~34 dangerous syscalls but denials are invisible — the strace monitor only traces filesystem syscalls. Users cannot verify the filter is working or see what the sandboxed process attempted. Additionally, the blocklist is all-or-nothing: users must choose between blocking all dangerous syscalls or allowing all of them (`--allow-all-syscalls`), with no way to selectively enable specific syscalls that their workload needs (e.g., ptrace for debuggers).

## What Changes

- Blocked syscall attempts appear as `SYSCALL` entries in the access log when seccomp is active
- New `SYSCALL` operation type alongside READ, WRITE, HTTP
- Monitor extends the strace trace expression to include blocked syscall names (conditional on seccomp being active)
- Seccomp package exports blocked syscall names for the monitor to use
- When `--allow-all-syscalls` is active (no seccomp filter), blocked syscalls are not traced — presence/absence of SYSCALL entries directly verifies filter status
- New `syscall:allow:<name>` config rules selectively permit specific blocked syscalls
- New `syscall:nolog:<name>` config rules suppress specific SYSCALL entries from display (like fs:nolog/net:nolog)
- Seccomp filter is built by removing `syscall:allow` entries from the default blocklist

**Security impact:** The BPF filter construction changes to exclude user-allowed syscalls. The allowed syscall names are validated against the known blocklist — unknown names are rejected at config parse time. The filter still blocks all non-allowed dangerous syscalls. `syscall:nolog` is display-only (same as fs:nolog/net:nolog) and does not affect enforcement. No new trust boundaries affected.

## Playbooks

### New Playbooks

(none)

### Modified Playbooks

- `monitoring-access`: Add use cases for observing seccomp-denied syscall attempts in the access log, verifying the filter is active, and suppressing expected denials with syscall:nolog
- `configuring-execave`: Add use case for selectively allowing blocked syscalls

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `access-log`: Add `SYSCALL` operation type to the log format requirement
- `monitor`: Add requirement for tracing seccomp-blocked syscalls when the filter is active, mapping them to SYSCALL/DENY entries with rule `seccomp`
- `config`: Add `syscall:allow:<name>` and `syscall:nolog:<name>` rule parsing and validation

## Impact

- `internal/seccomp/seccomp.go` — export blocked syscall names (refactor `blockedSyscalls` from `[]uint32` to struct slice with name+number); accept allowed set to exclude from filter
- `internal/accesslog/accesslog.go` — add `OperationSyscall` and `RuleSeccomp` constants
- `internal/monitor/monitor.go` — extend strace trace expression, add parser fallback for non-file syscalls, intercept blocked syscalls before access entry processing
- `internal/config/config.go` — parse `syscall:allow:<name>` and `syscall:nolog:<name>` rules; validate names against blocked list
- `internal/logfilter/logfilter.go` — add syscall nolog support
- `docs/security-model.md` — note seccomp denials now visible in access log; document syscall:allow trust implications
