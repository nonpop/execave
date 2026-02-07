## Why

When the monitor logs a denied access to a path that is a symlink (e.g., `/etc/resolv.conf → /run/systemd/resolve/stub-resolv.conf`), the log shows `DENY no-matching-rule` against the symlink path — even though a rule for that path exists. The denial is actually about the resolved target, but this is invisible in the log. Users cannot diagnose why a correctly-configured path is being denied.

Additionally, the rule resolver resolves symlinks in one shot on the host, skipping intermediate hops in symlink chains (A→B→C) and symlinks in intermediate path components (`/usr/lib` → `/usr/lib64`). The kernel inside bwrap resolves symlinks step by step — if any intermediate path is not mounted, the access fails. The monitor does not match this behavior and may incorrectly report access as allowed.

## What Changes

- The rule resolver walks paths component by component, resolving symlinks at each level and checking each against rules. This matches kernel path resolution inside bwrap's mount namespace.
- The access log emits one entry per symlink hop plus the final target access, making the full resolution chain visible.
- Symlinks whose targets fall under managed paths (`/tmp`, `/dev`, `/proc`) cannot be resolved from the host — these filesystems only exist inside the sandbox's mount namespace. Such accesses are logged as `UNKNOWN` with rule `symlink-target-unresolvable`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `monitor`: The log format requirement changes to specify behavior for symlink paths — multiple entries per symlink access instead of one.

## Impact

- Rule resolver (`internal/rules/`) and monitor (`internal/monitor/`).
- Security: Makes the monitor more restrictive (denies intermediate hops that were previously invisible). Sandbox enforcement, config parsing, and bwrap invocation unchanged.
- Trust boundaries: No change — no new inputs or boundaries.
- Config format: No changes. The access log output changes but is not a stable API.
