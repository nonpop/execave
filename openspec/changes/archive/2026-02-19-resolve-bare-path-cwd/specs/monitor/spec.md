## MODIFIED Requirements

### Requirement: Path resolution for *at() syscalls

Paths from `*at()` syscalls with a resolved fd SHALL be joined with the fd path to produce an absolute path.

The monitor SHALL track per-pid cwd from three sources in strace output:
1. AT_FDCWD annotations on `*at()` syscalls (the `<path>` in `AT_FDCWD<path>`).
2. `chdir(path)` syscalls — absolute paths recorded directly; relative paths joined with the pid's existing tracked cwd (if known).
3. `fchdir(fd<path>)` syscalls — the fd's annotated path recorded as the pid's cwd.

Cwd SHALL NOT be tracked during the bwrap setup phase (before the user command's execve), because setup-phase paths reflect the host namespace.

When a bare-path syscall (e.g., `access`, `readlink`) produces a relative path, the monitor SHALL resolve it by joining with the tracked cwd for that pid. When no cwd has been tracked for the pid, the path SHALL be forwarded as-is for logging with result `UNKNOWN` and rule `unresolved-relative-path`.

#### Scenario: Bare-path relative path resolved via tracked cwd
- **WHEN** monitoring is enabled
- **AND** pid 12345 has emitted `openat(AT_FDCWD</home/user/project>, ...)` (establishing cwd)
- **AND** pid 12345 subsequently calls `access(".git/config", R_OK)`
- **THEN** the monitor resolves the path to `/home/user/project/.git/config`
- **AND** the resolved path is checked against rules and logged with the appropriate result

#### Scenario: Bare-path relative path resolved via chdir tracking
- **WHEN** monitoring is enabled
- **AND** pid 12345 calls `chdir("/home/user/other")`
- **AND** pid 12345 subsequently calls `access("file.txt", R_OK)` with no intervening AT_FDCWD annotation
- **THEN** the monitor resolves the path to `/home/user/other/file.txt`

#### Scenario: Bare-path relative path resolved via fchdir tracking
- **WHEN** monitoring is enabled
- **AND** pid 12345 calls `fchdir(3</home/user/saved>)`
- **AND** pid 12345 subsequently calls `access("file.txt", R_OK)`
- **THEN** the monitor resolves the path to `/home/user/saved/file.txt`

#### Scenario: Unresolved relative path logged when no cwd tracked
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses a relative path (e.g., `foo/bar.txt`) via a bare-path syscall
- **AND** no cwd has been tracked for that pid (no prior AT_FDCWD annotation, chdir, or fchdir)
- **THEN** log contains line: `READ foo/bar.txt UNKNOWN unresolved-relative-path`

#### Scenario: Per-pid cwd isolation
- **WHEN** monitoring is enabled
- **AND** pid 12345 has cwd `/home/user/project-a` (from AT_FDCWD annotation)
- **AND** pid 12346 has cwd `/home/user/project-b` (from AT_FDCWD annotation)
- **AND** both pids call `access(".git/config", R_OK)`
- **THEN** pid 12345's access resolves to `/home/user/project-a/.git/config`
- **AND** pid 12346's access resolves to `/home/user/project-b/.git/config`

#### Scenario: Cwd not tracked during bwrap setup phase
- **WHEN** monitoring is enabled with bwrap
- **AND** AT_FDCWD annotations appear during the bwrap setup phase (before the user command's execve)
- **THEN** those annotations SHALL NOT be recorded as cwd for any pid
- **AND** cwd tracking begins only after the setup phase ends

#### Scenario: Relative chdir joined with existing cwd
- **WHEN** monitoring is enabled
- **AND** pid 12345 has cwd `/home/user/project` (from prior AT_FDCWD annotation)
- **AND** pid 12345 calls `chdir("subdir")`
- **THEN** the tracked cwd for pid 12345 is updated to `/home/user/project/subdir`

#### Scenario: Relative chdir with no prior cwd is ignored
- **WHEN** monitoring is enabled
- **AND** pid 12345 has no tracked cwd
- **AND** pid 12345 calls `chdir("subdir")`
- **THEN** no cwd is recorded for pid 12345
- **AND** subsequent bare-path relative calls from pid 12345 produce `UNKNOWN unresolved-relative-path`
