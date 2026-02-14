## MODIFIED Requirements

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

## REMOVED Requirements

### Requirement: Custom log path
**Reason**: File-based monitor logging is replaced by the web UI. The `--monitor` flag value is now a port number, not a file path.
**Migration**: Use `--monitor=PORT` to start the web UI on the specified port. Access logs are viewed in the browser.
