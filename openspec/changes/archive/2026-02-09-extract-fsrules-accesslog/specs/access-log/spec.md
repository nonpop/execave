## ADDED Requirements

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

