## MODIFIED Requirements

### Requirement: Monitor-only flags are command-scoped
Monitor-specific flags SHALL be defined on `monitor` and MUST NOT affect `run` or `config show`.

#### Scenario: Monitor flags accepted on monitor command
- **WHEN** the user runs `execave monitor --show-allowed --no-sandbox --output - -- true`
- **THEN** monitor mode runs with those options applied

#### Scenario: Monitor flags rejected on run command
- **WHEN** the user runs `execave run --show-allowed -- true`
- **THEN** execave exits with a CLI error indicating the flag is unknown for `run`
