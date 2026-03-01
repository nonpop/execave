## ADDED Requirements

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
