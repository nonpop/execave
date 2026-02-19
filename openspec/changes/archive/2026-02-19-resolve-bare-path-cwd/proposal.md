## Why

Some programs access files using relative paths through syscalls that strace cannot annotate with directory information. These accesses show up as `UNKNOWN unresolved-relative-path` in the access log — the monitor sees the relative path but can't determine which absolute path was accessed, so it can't match against rules. For example, `git status` in a normal (non-worktree) repo produces such entries for `.git/config`, `.git/info/exclude`, etc. These UNKNOWN entries reduce the usefulness of the access log for auditing and iterating on config.

## What Changes

- Track per-pid cwd from three sources in strace output: AT_FDCWD annotations on `*at()` syscalls, `chdir()` calls, and `fchdir()` calls.
- Use tracked cwd to resolve relative paths from bare-path syscalls before access checking.
- Fall through to existing `handleRelativePath` (UNKNOWN) when no cwd is known for a pid.
- Known limitation: clone/fork children don't inherit parent's tracked cwd; they get their cwd on their first AT_FDCWD annotation, chdir, or fchdir. In practice, the dynamic linker emits AT_FDCWD-annotated openat calls almost immediately after exec.

Security note: this change does not affect the sandbox enforcement boundary — bwrap enforces real permissions regardless of cwd tracking accuracy. However, incorrect path resolution in the log could mislead users into adding wrong paths to their rules. A stale or wrong tracked cwd would produce log entries for paths that don't match what the process actually accessed. The user should never allow access to paths they aren't prepared to expose, but accurate logging helps them make informed decisions.

## Playbooks

### New Playbooks

(none)

### Modified Playbooks

- `monitoring-access`: Relative paths from bare-path syscalls are now resolved and matched against rules, reducing UNKNOWN entries.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `monitor`: Broaden path resolution requirement to cover cwd tracking for bare-path syscalls. Add scenarios for cwd-resolved paths and the no-cwd fallback.

## Impact

- `internal/monitor/monitor.go` — parser (`parseLine` returns richer data), cwd tracking in `processStraceOutput`, new fchdir regex
- `internal/monitor/monitor_test.go` — new unit tests for cwd tracking, update existing test comments
- `openspec/specs/monitor/spec.md` — updated requirements and scenarios
- `docs/architecture.md` — check for monitor section references
