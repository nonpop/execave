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
- **THEN** access log SHALL be written containing entries for filesystem operations that occurred before the signal
- **AND** execave SHALL exit with the child's exit code (130 for SIGINT)
