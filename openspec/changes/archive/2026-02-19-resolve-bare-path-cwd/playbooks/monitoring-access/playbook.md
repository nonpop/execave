## ADDED Use Cases

### Use Case: Bare-path relative accesses resolved in access log

The user runs a command that uses bare-path syscalls with relative paths (e.g., `access(".git/config")`). The monitor resolves these to absolute paths using tracked per-pid cwd, so the access log shows proper rule matching instead of UNKNOWN.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** the sandboxed command uses bare-path syscalls with relative paths (e.g., `git status` in a non-worktree repo calls `access(".git/config", R_OK)`)
- **WHEN** the user runs `execave --monitor=9876 -- git status`
- **THEN** the web UI displays resolved absolute paths (e.g., `READ /home/user/project/.git/config OK fs:ro:/home/user/project`) instead of `UNKNOWN .git/config`

### Use Case: Unresolved relative path when no cwd tracked

The user runs a command where a bare-path relative syscall occurs before any cwd can be tracked for that pid. The monitor falls back to logging the relative path as UNKNOWN.

- **GIVEN** a config with filesystem rules
- **AND** the sandboxed command emits a bare-path relative syscall before any AT_FDCWD-annotated call from the same pid
- **WHEN** the user runs `execave --monitor=9876 -- <command>`
- **THEN** the web UI displays the unresolved relative path with result `UNKNOWN` and rule `unresolved-relative-path`
