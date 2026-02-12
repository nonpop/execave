## Why

The access log is currently written in batch after the sandbox exits: strace collects syscalls to a temp file, the child terminates, then the monitor post-processes the file. An upcoming interactive web view for live log inspection and configuration tuning needs log entries available while the sandbox is still running.

## What Changes

- Monitor processes strace output in real-time (pipe instead of temp file), writing access log entries as syscalls occur rather than after the child exits.
- Access log entries are flushed to the output file incrementally so external readers (e.g., the web view) can tail the file during execution.
- The SIGINT scenario simplifies: entries are already written before the signal arrives, so no special post-exit processing is needed to capture pre-signal activity.
- Network log entries from the proxy are already written in real-time (proxy calls `logger.Log` on each request); no change needed there.

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `monitor`: Processing model changes from batch post-processing (temp file after exit) to real-time streaming (pipe strace stdout during execution). Setup phase filtering and syscall parsing logic remain the same, but the data source changes from a file reader to a pipe reader. The SIGINT scenario requirements relax since entries are written incrementally.

## Impact

- `internal/monitor/` - Core change: replace temp file with pipe, process strace output concurrently with child execution.
- `cmd/execave/` - Simplify cleanup: log entries are already flushed during execution, defer cleanup just closes the file.
- `internal/accesslog/` - May need per-entry flush or line-buffered writing to ensure entries are visible to external readers immediately.
- Test fixtures that assert on log contents after execution should still pass (same entries, same order, just written earlier).
- No change to permission checks, rule resolution, sandbox boundaries, config parsing, or bwrap invocation. The same syscalls are logged with the same rules; only the timing of writes changes.
