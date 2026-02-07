# Monitor Capability

## Purpose

The monitor capability provides access logging for sandboxed processes, tracking filesystem operations and their results. It enables visibility into what resources sandboxed commands access without compromising sandbox isolation.

## Requirements

### Requirement: Monitor flag enables logging

The system SHALL support a `--monitor` flag that enables access logging while maintaining sandbox isolation.

#### Scenario: Monitor disabled by default
- **WHEN** user runs `execave -- <command>` without `--monitor`
- **THEN** command runs in sandbox
- **AND** no access log is created

#### Scenario: Monitor enabled
- **WHEN** user runs `execave --monitor -- <command>`
- **THEN** command runs in sandbox with access logging
- **AND** access log is written to `./execave-access.log`

#### Scenario: Access log written after child terminated by SIGINT
- **WHEN** user runs `execave --monitor -- <command>`
- **AND** the child process is terminated by SIGINT (e.g., ctrl-c)
- **THEN** access log SHALL be written containing entries for filesystem operations that occurred before the signal
- **AND** execave SHALL exit with the child's exit code (130 for SIGINT)

### Requirement: Custom log path

The system SHALL support custom log paths via `--monitor=<path>`. When a path is specified, the system SHALL write the access log to that path instead of the default location.

#### Scenario: Custom log path
- **WHEN** user runs `execave --monitor=/tmp/access.log -- <command>`
- **THEN** access log is written to `/tmp/access.log`

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

### Requirement: Path resolution for *at() syscalls

Paths from `*at()` syscalls with a resolved fd SHALL be joined with the fd path to produce an absolute path. When the fd path is unavailable and the syscall path is relative, the path SHALL be forwarded as-is for logging with result `UNKNOWN` and rule `unresolved-relative-path`.

#### Scenario: Unresolved relative path logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses a relative path (e.g., `foo/bar.txt`)
- **AND** the fd path for the `*at()` syscall is unavailable
- **THEN** log contains line: `READ foo/bar.txt UNKNOWN unresolved-relative-path`

### Requirement: Sandbox setup filtering

Internal sandbox setup operations SHOULD NOT appear in the access log. Only filesystem operations initiated by the sandboxed command SHOULD be logged. When the proxy-tunnel path is active (net rules present or monitoring enabled), the tunnel process adds one additional execve call to the setup phase (3 total instead of 2). The monitor SHALL detect setup phase completion based on the expected number of execve calls: 2 without proxy-tunnel, 3 with proxy-tunnel.

#### Scenario: Sandbox setup paths not logged without net rules
- **WHEN** monitoring is enabled
- **AND** config contains no net rules
- **AND** sandbox setup creates internal paths (e.g., `/newroot`, `/oldroot`)
- **THEN** log does NOT contain entries for sandbox setup paths

#### Scenario: Sandbox setup paths not logged with net rules
- **WHEN** monitoring is enabled
- **AND** config contains net rules
- **AND** sandbox setup creates internal paths including tunnel setup
- **THEN** log does NOT contain entries for sandbox or tunnel setup paths

#### Scenario: Tunnel execve not counted as user activity
- **WHEN** monitoring is enabled
- **AND** config contains net rules
- **AND** the tunnel process starts (execve)
- **THEN** the tunnel's execve is counted toward the expected 3 setup execves and its operations are NOT logged to the access log

#### Scenario: Sandbox setup paths not logged with monitoring and no net rules
- **WHEN** monitoring is enabled
- **AND** config contains no net rules
- **AND** proxy-tunnel is started for network logging
- **THEN** log does NOT contain entries for sandbox or tunnel setup paths
- **AND** setup phase expects 3 execves (same as with net rules)

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
