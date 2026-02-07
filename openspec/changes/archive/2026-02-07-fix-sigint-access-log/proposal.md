## Why

When running with `--monitor`, pressing ctrl-c (SIGINT) kills the execave process before it can write the access log. SIGINT is delivered to the entire foreground process group — both execave and strace/bwrap/child. Go's default SIGINT handler terminates execave immediately, so `processStraceResults()` is never called and the access log is lost.

## What Changes

- Execave ignores SIGINT during child process execution so that only strace/bwrap/child handle the signal. After the child exits, execave processes strace output and writes the access log normally.
- This applies to both monitor mode (strace wraps bwrap) and sandbox-only mode (bwrap directly), since the same problem exists in both paths.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `monitor`: Add requirement that the access log is written even when the child process is terminated by a signal (e.g., SIGINT from ctrl-c).

## Impact

- `cmd/execave/main.go` — signal handling setup before child execution
- `internal/sandbox/sandbox.go` — potentially, if signal handling is centralized
- `internal/monitor/monitor.go` — potentially, if signal handling is per-executor
- No config format changes, no API changes, no dependency changes.
- **Security impact:** This change does not affect permission checks, rule resolution, sandbox boundaries, config parsing, or bwrap invocation. The sandbox is already running when the signal arrives; we are only ensuring the Go process survives long enough to write the access log. No trust boundary changes.
