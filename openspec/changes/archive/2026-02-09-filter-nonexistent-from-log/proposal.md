## Why

The access log is a debugging tool. Nonexistent file read attempts (library search path probing, config fallbacks, locale lookups) create noise that obscures the actual file accesses a user cares about. Filtering read operations to nonexistent paths makes the log immediately useful for debugging. Write operations to nonexistent paths represent the program's intent to create files and should remain visible.

## What Changes

- After the sandboxed process exits, the monitor checks each logged path's existence on the host filesystem before writing it to the access log
- Read operations to nonexistent paths are silently dropped from the log
- Write operations are logged regardless of path existence (shows intent to create files)

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `monitor`: The "Non-existent path not resolved" scenario changes — nonexistent paths are no longer logged regardless of OK/DENY status. The log format, deduplication, and all other behaviors are unchanged.

## Impact

- Monitor (`internal/monitor/`).
- Security: No impact. This change only affects the post-hoc access log, not sandbox enforcement or rule resolution. The monitor runs after the sandboxed process has exited. No permission checks, rule resolution, sandbox boundaries, config parsing, or bwrap invocation are affected.
- Trust boundaries: No change — no new inputs or boundaries. The access log is produced entirely in the trusted execave process after the untrusted sandboxed process has exited. The `os.Stat` calls operate on the trusted host filesystem.
- Config format: No changes. The access log output changes but is not a stable API.
