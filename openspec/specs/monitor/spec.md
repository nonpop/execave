# Monitor Capability

## Purpose

The monitor capability provides access logging for sandboxed processes, tracking filesystem operations and their results. It enables visibility into what resources sandboxed commands access without compromising sandbox isolation.

## Requirements

### Requirement: Real-time access log writing

Access log entries SHALL be stored in memory as syscalls are processed during sandbox execution, not batched after the sandbox exits. Each entry SHALL be available to consumers immediately, without waiting for the sandbox to exit.

Network entries from the proxy are stored in real-time and are unaffected by this change.

#### Scenario: Log entries available during execution

- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `<tmp>/data/file.txt`
- **AND** config contains `fs:ro:<tmp>/data`
- **THEN** the entry for `READ <tmp>/data/file.txt OK fs:ro:<tmp>/data` SHALL be available via the Logger while the sandbox is still running

#### Scenario: Log entries appear in syscall order

- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `<tmp>/data/a.txt` then writes `<tmp>/data/b.txt`
- **AND** config contains `fs:rw:<tmp>/data`
- **THEN** the READ entry for `a.txt` SHALL appear before the WRITE entry for `b.txt`

### Requirement: Operation type mapping

Filesystem operations MUST be classified as READ or WRITE for logging purposes:
- READ: querying file metadata, reading file contents, listing directory entries, resolving symlinks, checking access permissions, executing files
- WRITE: creating files, writing file contents, deleting files or directories, creating directories, renaming paths, truncating files, changing permissions or ownership

#### Scenario: Querying file metadata logged as read
- **WHEN** monitoring is enabled
- **AND** sandboxed process queries metadata of `/etc/passwd`
- **THEN** log contains a READ entry for `/etc/passwd`

#### Scenario: Creating directory logged as write
- **WHEN** monitoring is enabled
- **AND** sandboxed process creates directory `/home/user/project/newdir`
- **THEN** log contains a WRITE entry for `/home/user/project/newdir`

#### Scenario: Reading file contents logged as read
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads file contents of `<tmp>/data/file.txt` via `openat(O_RDONLY)`
- **AND** config contains `fs:ro:<tmp>/data`
- **THEN** log contains a READ entry for `<tmp>/data/file.txt`

#### Scenario: Writing file contents logged as write
- **WHEN** monitoring is enabled
- **AND** sandboxed process writes to `<tmp>/data/output.txt` via `openat(O_WRONLY|O_CREAT)`
- **AND** config contains `fs:rw:<tmp>/data`
- **THEN** log contains a WRITE entry for `<tmp>/data/output.txt`

### Requirement: Path resolution for *at() syscalls

Paths from `*at()` syscalls with a resolved fd SHALL be joined with the fd path to produce an absolute path. When the path argument is absolute, the dirfd is ignored.

When a numeric dirfd is annotated with a path by strace (`fd<path>`) and the path argument is empty (AT_EMPTY_PATH usage), the fd's annotated path SHALL be used as the accessed path.

The monitor SHALL track per-pid cwd from three sources in strace output:
1. AT_FDCWD annotations on `*at()` syscalls (the `<path>` in `AT_FDCWD<path>`).
2. `chdir(path)` syscalls — absolute paths recorded directly; relative paths joined with the pid's existing tracked cwd (if known).
3. `fchdir(fd<path>)` syscalls — the fd's annotated path recorded as the pid's cwd.

Cwd SHALL NOT be tracked during the bwrap setup phase (before the user command's execve), because setup-phase paths reflect the host namespace.

When a bare-path syscall (e.g., `access`, `readlink`) produces a relative path, the monitor SHALL resolve it by joining with the tracked cwd for that pid. When no cwd has been tracked for the pid, the path SHALL be forwarded as-is for logging with result `UNKNOWN` and rule `unresolved-relative-path`.

When a monitored process exits, the monitor SHALL clear its tracked cwd entry. New pids (from fork/exec) start with no tracked cwd and do not inherit the parent's cwd.

#### Scenario: Absolute dirfd ignored

- **WHEN** monitoring is enabled
- **AND** a sandboxed process calls an `*at()` syscall with an absolute path argument
- **THEN** the dirfd (AT_FDCWD or numeric) is ignored and the absolute path is logged directly

#### Scenario: AT_FDCWD resolves with tracked cwd

- **WHEN** monitoring is enabled
- **AND** strace annotates `AT_FDCWD` with a directory path (e.g., `openat(AT_FDCWD</dir>, "file", O_RDONLY)`)
- **AND** the path argument is relative
- **THEN** the monitor joins the annotation with the relative path to produce an absolute path
- **AND** the absolute path is logged with the appropriate result

#### Scenario: AT_FDCWD unresolvable when no cwd tracked

- **WHEN** monitoring is enabled
- **AND** strace cannot annotate `AT_FDCWD` (no `<path>` annotation)
- **AND** no cwd has been tracked for that pid (no prior AT_FDCWD annotation, chdir, or fchdir)
- **AND** the path argument is relative
- **THEN** the path is logged as UNKNOWN with rule `unresolved-relative-path`

#### Scenario: Relative dirfd resolves with tracked cwd

- **WHEN** monitoring is enabled
- **AND** strace annotates a numeric dirfd with a directory path (e.g., `openat(3</dir>, "file", O_RDONLY)`)
- **AND** the path argument is relative
- **THEN** the monitor joins the fd annotation with the relative path to produce an absolute path
- **AND** the absolute path is logged with the appropriate result

#### Scenario: Relative dirfd unresolvable when no cwd tracked

- **WHEN** monitoring is enabled
- **AND** a numeric dirfd has no path annotation (strace could not resolve it)
- **AND** no cwd has been tracked for that pid
- **AND** the path argument is relative
- **THEN** the path is logged as UNKNOWN with rule `unresolved-relative-path`

#### Scenario: Empty path with AT_EMPTY_PATH

- **WHEN** monitoring is enabled
- **AND** a sandboxed process calls an `*at()` syscall with an empty path and a numeric dirfd annotated with an absolute path (AT_EMPTY_PATH usage)
- **THEN** the fd's annotated path is used as the accessed path and logged with the appropriate result

#### Scenario: Chdir updates cwd for pid

- **WHEN** monitoring is enabled
- **AND** a process calls `chdir(path)` successfully
- **THEN** the monitor updates the tracked cwd for that pid
- **AND** subsequent bare-path syscalls from that pid are resolved against the new cwd

#### Scenario: Fchdir updates cwd for pid

- **WHEN** monitoring is enabled
- **AND** a process calls `fchdir(fd)` successfully
- **THEN** the monitor updates the tracked cwd for that pid to the fd's annotated path
- **AND** subsequent bare-path syscalls from that pid are resolved against the new cwd

#### Scenario: Cwd cleared on process exit

- **WHEN** monitoring is enabled
- **AND** a monitored process exits
- **THEN** the monitor clears the tracked cwd for that pid
- **AND** a subsequent monitored run starts with no inherited cwd state

#### Scenario: Cwd not inherited by new pid

- **WHEN** monitoring is enabled
- **AND** a new process is created (via fork/exec) from a parent that has a tracked cwd
- **THEN** the new pid starts with no tracked cwd
- **AND** its bare-path syscalls are logged as UNKNOWN until it establishes its own cwd

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

### Requirement: Symlink path resolution in access logging

When the accessed path contains symlinks, the monitor SHALL resolve them component by component, matching how the kernel resolves paths inside bwrap's mount namespace. The monitor SHALL distinguish between symlinks at rule boundaries and symlinks within mounted directories:

- **Rule-boundary symlinks** (the symlink path exactly matches a config rule path): bwrap resolves these at mount time. The monitor SHALL NOT resolve them and SHALL log the access against the original (unresolved) path.
- **Symlinks within a rule's scope** (the symlink path is a descendant of a config rule path, or has no matching rule): the kernel resolves these at access time inside the sandbox. The monitor SHALL resolve them step by step, logging a `READ` entry for each symlink hop, followed by the final target access with the original operation.

When a path does not exist on the host filesystem, the resolver SHALL NOT attempt symlink resolution for that path. Non-existent paths are not symlinks and MUST be treated as literal paths.

If any hop in the resolution chain is denied (no matching rule or insufficient permission), the chain SHALL stop and subsequent hops and the final target SHALL NOT be logged.

The symlink resolution depth SHALL be limited to 40 links (matching the Linux kernel's `MAXSYMLINKS`). Exceeding this limit SHALL be treated as a denial.

The monitor's access log SHALL be consistent with sandbox enforcement: if the final relevant log entry for an access is `DENY`, the sandbox MUST have denied the operation; if `OK`, the sandbox MUST have allowed it.

#### Scenario: Rule-boundary symlink logged without resolution

- **WHEN** monitoring is enabled
- **AND** `<tmp>/link-file` is a symlink to `<tmp>/target-file`
- **AND** config contains `fs:ro:<tmp>/link-file`
- **AND** sandboxed process reads `<tmp>/link-file`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/link-file OK fs:ro:<tmp>/link-file`
- **AND** log does NOT contain an entry for `<tmp>/target-file`

#### Scenario: Rule-boundary symlink in intermediate component logged without resolution

- **WHEN** monitoring is enabled
- **AND** `<tmp>/link-dir` is a symlink to `<tmp>/real-dir`
- **AND** `<tmp>/real-dir/file.txt` exists
- **AND** config contains `fs:ro:<tmp>/link-dir`
- **AND** sandboxed process reads `<tmp>/link-dir/file.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/link-dir/file.txt OK fs:ro:<tmp>/link-dir`
- **AND** log does NOT contain an entry for `<tmp>/real-dir/file.txt`

#### Scenario: Symlink within mount resolved and logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a symlink to `<tmp>/mount/target.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/mount/link.txt OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/mount/target.txt OK fs:ro:<tmp>/mount`

#### Scenario: Relative symlink within mount resolved and logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a relative symlink to `<tmp>/mount/target.txt`
- **AND** `<tmp>/mount/target.txt` is a regular file
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/mount/link.txt OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/mount/target.txt OK fs:ro:<tmp>/mount`

#### Scenario: Relative symlink chain resolved with all hops logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link` is a relative symlink to `<tmp>/mount/hop2`
- **AND** `<tmp>/mount/hop2` is a relative symlink to `<tmp>/mount/final.txt`
- **AND** `<tmp>/mount/final.txt` is a regular file
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link`
- **THEN** the read succeeds
- **AND** log contains in order:
  - `READ <tmp>/mount/link OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/hop2 OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/final.txt OK fs:ro:<tmp>/mount`

#### Scenario: Symlink within mount pointing outside rules denied

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/escape.txt` is a symlink to `<tmp>/outside/secret.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** no rule matches `<tmp>/outside`
- **AND** sandboxed process reads `<tmp>/mount/escape.txt`
- **THEN** the read fails
- **AND** log contains: `READ <tmp>/mount/escape.txt OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/outside/secret.txt DENY no-matching-rule`

#### Scenario: Multi-hop symlink chain within mount

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/hop1` is a symlink to `<tmp>/mount/hop2`
- **AND** `<tmp>/mount/hop2` is a symlink to `<tmp>/mount/final.txt`
- **AND** `<tmp>/mount/final.txt` is a regular file
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/hop1`
- **THEN** the read succeeds
- **AND** log contains in order:
  - `READ <tmp>/mount/hop1 OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/hop2 OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/final.txt OK fs:ro:<tmp>/mount`

#### Scenario: Multi-hop chain breaks at denied intermediate hop

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/hop1` is a symlink to `<tmp>/nomatch/hop2`
- **AND** `<tmp>/nomatch/hop2` is a symlink to `<tmp>/mount/final.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** no rule matches `<tmp>/nomatch`
- **AND** sandboxed process reads `<tmp>/mount/hop1`
- **THEN** the read fails
- **AND** log contains: `READ <tmp>/mount/hop1 OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/nomatch/hop2 DENY no-matching-rule`
- **AND** log does NOT contain an entry for `<tmp>/mount/final.txt`

#### Scenario: Symlink in intermediate path component resolved

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/subdir-link` is a symlink to `<tmp>/mount/subdir-real`
- **AND** `<tmp>/mount/subdir-real/file.txt` exists
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/subdir-link/file.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/mount/subdir-link OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/mount/subdir-real/file.txt OK fs:ro:<tmp>/mount`

#### Scenario: Write operation through symlink within mount

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a symlink to `<tmp>/mount/real.txt`
- **AND** config contains `fs:rw:<tmp>/mount`
- **AND** sandboxed process writes to `<tmp>/mount/link.txt`
- **THEN** the write succeeds
- **AND** log contains: `READ <tmp>/mount/link.txt OK fs:rw:<tmp>/mount`
- **AND** log contains: `WRITE <tmp>/mount/real.txt OK fs:rw:<tmp>/mount`

#### Scenario: Write through symlink to read-only target denied

- **WHEN** monitoring is enabled
- **AND** `<tmp>/writable/link.txt` is a symlink to `<tmp>/readonly/file.txt`
- **AND** config contains `fs:rw:<tmp>/writable` and `fs:ro:<tmp>/readonly`
- **AND** sandboxed process writes to `<tmp>/writable/link.txt`
- **THEN** the write fails
- **AND** log contains: `READ <tmp>/writable/link.txt OK fs:rw:<tmp>/writable`
- **AND** log contains: `WRITE <tmp>/readonly/file.txt DENY fs:ro:<tmp>/readonly`

#### Scenario: Write through read-only symlink to writable target allowed

- **WHEN** monitoring is enabled
- **AND** `<tmp>/readonly/link.txt` is a symlink to `<tmp>/writable/file.txt`
- **AND** config contains `fs:ro:<tmp>/readonly` and `fs:rw:<tmp>/writable`
- **AND** sandboxed process writes to `<tmp>/readonly/link.txt`
- **THEN** the write succeeds
- **AND** log contains: `READ <tmp>/readonly/link.txt OK fs:ro:<tmp>/readonly`
- **AND** log contains: `WRITE <tmp>/writable/file.txt OK fs:rw:<tmp>/writable`

#### Scenario: Symlink depth limit exceeded

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/loop-a` is a symlink to `<tmp>/mount/loop-b`
- **AND** `<tmp>/mount/loop-b` is a symlink to `<tmp>/mount/loop-a`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/loop-a`
- **THEN** the read fails
- **AND** the access is logged as denied
- **AND** log contains: `READ <tmp>/mount/loop-a DENY symlink-depth-limit-exceeded`
  (the hop that exceeded the limit is logged with a distinct reason)

#### Scenario: Resolved symlink paths deduplicated

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link1` and `<tmp>/mount/link2` are both symlinks to `<tmp>/mount/target.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link1` then `<tmp>/mount/link2`
- **THEN** both reads succeed
- **AND** log contains exactly one `READ` entry for `<tmp>/mount/target.txt`

#### Scenario: Non-existent path not resolved

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/noexist.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to read `<tmp>/mount/noexist.txt`
- **THEN** the read fails
- **AND** log does NOT contain an entry for `<tmp>/mount/noexist.txt`

#### Scenario: Symlink through managed path logged as unknown

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a symlink to `/tmp/target.txt`
- **AND** config contains `fs:rw:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link.txt`
- **THEN** the read fails (target does not exist on sandbox tmpfs)
- **AND** log contains: `READ <tmp>/mount/link.txt UNKNOWN symlink-target-unresolvable`

### Requirement: Non-existent path filtering for reads

Read operations to paths that do not exist on the host filesystem SHALL NOT be logged. This filters noise from programs probing nonexistent paths (library search paths, config fallbacks). Write operations to nonexistent paths SHALL be logged, as they represent the program's intent to create files.

#### Scenario: Non-existent read filtered from log

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/noexist.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to read `<tmp>/mount/noexist.txt`
- **THEN** the read fails
- **AND** log does NOT contain an entry for `<tmp>/mount/noexist.txt`

#### Scenario: Non-existent write logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/newfile.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to write `<tmp>/mount/newfile.txt`
- **THEN** the write fails (read-only)
- **AND** log contains `WRITE <tmp>/mount/newfile.txt DENY`

#### Scenario: Stat error other than ENOENT still logged (fail-safe)

- **WHEN** monitoring is enabled
- **AND** `<tmp>/restricted/secret.txt` exists but stat fails with permission denied
- **AND** config contains `fs:ro:<tmp>`
- **AND** sandboxed process attempts to read `<tmp>/restricted/secret.txt`
- **THEN** log contains `READ <tmp>/restricted/secret.txt DENY` (fail-safe: when in doubt, log it)

### Requirement: Bwrap setup phase detection

When bwrap is used, strace captures bwrap's sandbox setup (namespace, mount, pivot_root, etc.) before the user command starts. The monitor SHALL skip setup lines and begin processing from the user command's execve. Setup operations (mounts, namespace manipulation) SHALL NOT appear in the access log.

When the network tunnel is configured, the monitor SHALL expect an additional execve for the tunnel between bwrap's own execve and the user command's execve (3 total instead of 2).

When the strace output ends before the expected number of execves (e.g., the tunnel or user command crashes during startup), the monitor SHALL still produce log entries for the last process transition and any subsequent operations. This ensures monitoring remains useful for diagnosing startup failures.

#### Scenario: Setup phase lines skipped until user command execve

- **WHEN** monitoring is enabled with bwrap
- **AND** strace output contains bwrap's setup operations (mount, namespace, etc.)
- **AND** the user command's execve follows the setup phase
- **THEN** log entries are produced from the user command's execve onward
- **AND** bwrap setup operations do not appear in the log

#### Scenario: Incomplete execve chain still produces entries

- **WHEN** monitoring is enabled with bwrap and network tunnel expected
- **AND** the strace output ends before the user command's execve (e.g., the tunnel crashes)
- **THEN** log entries are still produced for the last process transition and subsequent operations
- **AND** the monitor does not produce zero entries

### Requirement: Extra environment variable injection

When `extraEnv` is non-nil, the monitor SHALL set the strace-traced child process's environment to the current process's environment (`os.Environ()`) extended with the entries in `extraEnv`. This allows the caller to inject variables such as `HTTP_PROXY` into the traced command's environment without affecting the monitor process itself.

#### Scenario: Extra env vars injected into traced command

- **WHEN** the monitor is constructed with `extraEnv` containing `HTTP_PROXY=http://127.0.0.1:12345`
- **AND** Run is called
- **THEN** the strace-traced command receives `HTTP_PROXY=http://127.0.0.1:12345` in its environment

#### Scenario: Nil extraEnv inherits parent environment unchanged

- **WHEN** the monitor is constructed with `extraEnv=nil`
- **AND** Run is called
- **THEN** the strace-traced command inherits the parent process's environment unchanged

### Requirement: Monitor command entrypoint
Monitoring SHALL be invoked via the `monitor` subcommand, not via root monitor flags.

#### Scenario: Monitor command runs text logging mode
- **WHEN** the user runs `execave monitor --output - -- /bin/true`
- **THEN** execave runs monitored execution and writes text log output to stderr after process exit

#### Scenario: Monitor file output mode remains available
- **WHEN** the user runs `execave monitor --output access.log -- /bin/true`
- **THEN** execave writes monitor text log output to `access.log` during execution

### Requirement: No-sandbox monitor option remains monitor-scoped
The `--no-sandbox` option SHALL remain available only in monitor mode and preserve existing requirement that monitored mode is active.

#### Scenario: No-sandbox runs under monitor command
- **WHEN** the user runs `execave monitor --no-sandbox --output - -- /bin/true`
- **THEN** execave runs unsandboxed monitored mode and produces monitor output
