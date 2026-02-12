## ADDED Requirements

### Requirement: Real-time access log writing

Access log entries SHALL be written to the log file as syscalls are processed during sandbox execution, not batched after the sandbox exits. Each entry SHALL be visible to external readers (e.g., `tail -f`) immediately after it is written, without waiting for the sandbox to exit or for an explicit flush.

Network entries from the proxy are already written in real-time and are unaffected by this change.

#### Scenario: Log entries visible during execution

- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `<tmp>/data/file.txt`
- **AND** config contains `fs:ro:<tmp>/data`
- **AND** an external reader is watching the log file
- **THEN** the entry `READ <tmp>/data/file.txt OK fs:ro:<tmp>/data` SHALL be visible in the log file while the sandbox is still running

#### Scenario: Log entries appear in syscall order

- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `<tmp>/data/a.txt` then writes `<tmp>/data/b.txt`
- **AND** config contains `fs:rw:<tmp>/data`
- **THEN** the READ entry for `a.txt` SHALL appear in the log before the WRITE entry for `b.txt`

### Requirement: Thread-safe access logging

The access logger SHALL be safe for concurrent use by the monitor and proxy. When the monitor writes filesystem entries and the proxy writes network entries concurrently, no entries SHALL be lost or corrupted, and deduplication SHALL remain correct.

#### Scenario: Concurrent filesystem and network entries

- **WHEN** monitoring is enabled
- **AND** config contains `fs:ro:<tmp>/data` and `net:https:api.example.com:443`
- **AND** sandboxed process reads `<tmp>/data/file.txt` and makes an HTTPS request to `api.example.com:443` concurrently
- **THEN** log contains both `READ <tmp>/data/file.txt OK fs:ro:<tmp>/data` and `HTTPS api.example.com:443 OK net:https:api.example.com:443`
- **AND** no entries are lost or corrupted

## MODIFIED Requirements

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
- **THEN** access log SHALL contain entries for filesystem operations that occurred before the signal
- **AND** execave SHALL exit with the child's exit code (130 for SIGINT)
