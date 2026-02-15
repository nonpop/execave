## Why

Enable restarting the sandboxed process via the web UI so users can iterate quickly with the upcoming config editor.

## What Changes

- The web UI gains controls to start and stop monitored sandbox runs.
- Starting a run always stops any active run first, so "restart" is just another start.
- Each new run starts with a fresh access log — previous entries are cleared.
- The existing access log display and real-time streaming continue to work as before.

## Playbooks

### New Playbooks

- `iterating-config`: The user starts a monitored run from the web UI, observes access patterns, stops or restarts the process, and repeats. This is the foundation for the interactive config editing loop.

### Modified Playbooks

None.

## Capabilities

### New Capabilities

- `runner`: Run lifecycle management — starting/stopping sandbox+monitor executions, status tracking, and access log lifecycle. Each start produces a fresh access log and exposes status via the existing `StatusProvider` interface.

### Modified Capabilities

- `web-ui`: New HTTP endpoints for run control (start/stop). The web UI transitions from a passive observer to an active controller of the run lifecycle.

## Impact

- **New package**: `internal/runner/`
- **Modified**: `cmd/execave/main.go` — `runMonitored` delegates to runner instead of inline orchestration
- **Modified**: `internal/webui/` — new run control endpoints, Server accepts a runner
- **Interface**: Runner implements `webui.StatusProvider`; webui.Server receives a Runner's status/logger instead of a standalone tracker
- **No config format changes**

## Security Impact

Same sandbox+monitor code paths — no changes to permission checks, rule resolution, or bwrap invocation. Run control endpoints trigger re-runs with the CLI-provided command; they do not accept arbitrary commands. No config format changes.
