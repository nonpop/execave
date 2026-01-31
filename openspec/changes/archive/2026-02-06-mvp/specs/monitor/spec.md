## ADDED Requirements

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

### Requirement: Custom log path

The system SHALL support custom log paths via `--monitor=<path>`. When a path is specified, the system SHALL write the access log to that path instead of the default location.

#### Scenario: Custom log path
- **WHEN** user runs `execave --monitor=/tmp/access.log -- <command>`
- **THEN** access log is written to `/tmp/access.log`

### Requirement: Log format

Each log entry SHALL be a single line in the format: `<OP> <PATH> <RESULT> <RULE>` where:
- `<OP>` is `READ` or `WRITE`
- `<PATH>` is the path accessed (absolute when resolved, relative otherwise)
- `<RESULT>` is `OK`, `DENY`, or `UNKNOWN`
- `<RULE>` is the matching rule (e.g., `fs:ro:/etc`), `no-matching-rule`, or `unresolved-relative-path`

Paths from `*at()` syscalls with a resolved fd are joined with the fd path to produce an absolute path. When the fd path is unavailable and the syscall path is relative, the path is logged as-is with result `UNKNOWN` and rule `unresolved-relative-path`, since the access cannot be evaluated against config rules without the full path.

#### Scenario: Allowed read logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `/etc/passwd`
- **AND** config contains `fs:ro:/etc`
- **THEN** log contains line: `READ /etc/passwd OK fs:ro:/etc`

#### Scenario: Denied write logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process attempts to write `/home/user/project/.git/config`
- **AND** config contains `fs:ro:/home/user/project/.git`
- **THEN** log contains line: `WRITE /home/user/project/.git/config DENY fs:ro:/home/user/project/.git`

#### Scenario: No-access rule logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process attempts to read `/home/user/project/.env`
- **AND** config contains `fs:none:/home/user/project/.env`
- **THEN** log contains line: `READ /home/user/project/.env DENY fs:none:/home/user/project/.env`

#### Scenario: No matching rule logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process attempts to read `/opt/secret`
- **AND** no rule matches `/opt/secret`
- **THEN** log contains line: `READ /opt/secret DENY no-matching-rule`

#### Scenario: Unresolved relative path logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses a relative path (e.g., `foo/bar.txt`)
- **AND** the fd path for the `*at()` syscall is unavailable
- **THEN** log contains line: `READ foo/bar.txt UNKNOWN unresolved-relative-path`

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

### Requirement: Log deduplication

Each unique (operation, path) pair SHALL be logged at most once, regardless of how many times the access occurs. Read and write to the same path are distinct pairs.

#### Scenario: Repeated reads deduplicated
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `/etc/passwd` three times
- **THEN** log contains exactly one READ entry for `/etc/passwd`

#### Scenario: Read and write both logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads and writes `/home/user/project/file.txt`
- **AND** config contains `fs:rw:/home/user/project`
- **THEN** log contains one READ entry and one WRITE entry for the path (two lines total)

#### Scenario: Repeated writes deduplicated
- **WHEN** monitoring is enabled
- **AND** sandboxed process writes to `/home/user/project/out.txt` multiple times
- **THEN** log contains exactly one WRITE entry for `/home/user/project/out.txt`

### Requirement: Infrastructure path filtering

Infrastructure paths (`/dev`, `/proc`, `/tmp`) and their descendants SHOULD NOT be logged, as they are not governed by config rules.

#### Scenario: Infrastructure paths not logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses `/proc/self/status`
- **THEN** log does NOT contain any entry for `/proc/self/status`

#### Scenario: Infrastructure writes not logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process writes to `/dev/tty`
- **THEN** log does NOT contain any entry for `/dev/tty`

#### Scenario: Filesystem paths still logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses `/etc/passwd`
- **THEN** log contains an entry for `/etc/passwd`

### Requirement: Sandbox setup filtering

Internal sandbox setup operations SHOULD NOT appear in the access log. Only filesystem operations initiated by the sandboxed command SHOULD be logged.

#### Scenario: Sandbox setup paths not logged
- **WHEN** monitoring is enabled
- **AND** sandbox setup creates internal paths (e.g., `/newroot`, `/oldroot`)
- **THEN** log does NOT contain entries for sandbox setup paths

#### Scenario: Namespace operations not logged
- **WHEN** monitoring is enabled
- **AND** sandbox setup performs namespace operations (e.g., writing `uid_map`, `gid_map`)
- **THEN** log does NOT contain entries for namespace setup operations
