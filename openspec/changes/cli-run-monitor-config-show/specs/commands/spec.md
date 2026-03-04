## ADDED Requirements

### Requirement: Root command routing and global config flag
The CLI SHALL expose `run`, `monitor`, and `config` subcommands. `--config` MUST be accepted as a global root flag before any subcommand and used as the config path for that invocation.

#### Scenario: Global config flag applies to run
- **WHEN** the user runs `execave --config /home/user/alt.toml run -- true`
- **THEN** execave loads `/home/user/alt.toml` before executing `true`

#### Scenario: Global config flag applies to monitor
- **WHEN** the user runs `execave --config /home/user/alt.toml monitor --output - -- true`
- **THEN** execave loads `/home/user/alt.toml` before starting monitor mode

#### Scenario: Global config flag applies to config show
- **WHEN** the user runs `execave --config /home/user/alt.toml config show`
- **THEN** execave renders the effective config from `/home/user/alt.toml`

### Requirement: Explicit and implicit run behavior
The CLI SHALL support explicit execution via `run` and implicit execution when a bare command is provided at root.

#### Scenario: Explicit run executes command
- **WHEN** the user runs `execave run -- /bin/echo hello`
- **THEN** execave executes `/bin/echo hello` with sandboxed run behavior

#### Scenario: Implicit run executes command
- **WHEN** the user runs `execave -- /bin/echo hello`
- **THEN** execave executes `/bin/echo hello` with behavior equivalent to `execave run -- /bin/echo hello`

### Requirement: Monitor-only flags are command-scoped
Monitor-specific flags SHALL be defined on `monitor` and MUST NOT affect `run` or `config show`.

#### Scenario: Monitor flags accepted on monitor command
- **WHEN** the user runs `execave monitor --show-allowed --show-nolog --no-sandbox --output - -- true`
- **THEN** monitor mode runs with those options applied

#### Scenario: Monitor flags rejected on run command
- **WHEN** the user runs `execave run --show-allowed -- true`
- **THEN** execave exits with a CLI error indicating the flag is unknown for `run`
