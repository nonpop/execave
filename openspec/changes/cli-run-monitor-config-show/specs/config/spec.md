## ADDED Requirements

### Requirement: Effective config rendering
The config capability SHALL provide effective merged config rendering through `execave config show`, using the same layered load, deduplication, and validation path as command execution.

#### Scenario: Show effective config from default path
- **WHEN** the user runs `execave config show`
- **THEN** execave prints TOML representing the effective merged config loaded from `./execave.toml`

#### Scenario: Show effective config from custom path
- **WHEN** the user runs `execave --config /home/user/project/execave.toml config show`
- **THEN** execave prints TOML representing the effective merged config loaded from `/home/user/project/execave.toml`

### Requirement: Effective config output format and provenance
Effective config output SHALL be TOML with typed sections (`fs`, `net`, `syscall`) and SHALL include source-path provenance as comment lines for emitted rules.

#### Scenario: Output contains typed sections
- **WHEN** `config show` succeeds
- **THEN** stdout contains TOML arrays for configured sections (`fs`, `net`, and/or `syscall`) using rule bodies consistent with current config format

#### Scenario: Output includes source comments for each emitted rule
- **WHEN** `config show` emits a rule originating from layered config files
- **THEN** the emitted TOML includes one or more comment lines indicating source file path provenance adjacent to that rule
