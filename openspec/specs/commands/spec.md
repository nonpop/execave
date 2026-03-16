# Commands Capability

## Purpose

The commands capability defines the CLI command structure — root command routing, subcommands (`run`, `monitor`, `config`), global flags, and command-scoped flags.

## Requirements

### Requirement: Root command routing and global config flag
The CLI SHALL expose `run`, `monitor`, and `config` subcommands. `--config` MUST be accepted as a global root flag before any subcommand and used as the config path for that invocation. `--no-config`, `--fs`, `--net`, `--syscall`, `--env`, and `--extends` MUST also be accepted as global root flags.

#### Scenario: Global config flag applies to run
- **WHEN** the user runs `execave --config /home/user/alt.toml run -- true`
- **THEN** execave loads `/home/user/alt.toml` before executing `true`

#### Scenario: Global config flag applies to monitor
- **WHEN** the user runs `execave --config /home/user/alt.toml monitor --output - -- true`
- **THEN** execave loads `/home/user/alt.toml` before starting monitor mode

#### Scenario: Global config flag applies to config show
- **WHEN** the user runs `execave --config /home/user/alt.toml config show`
- **THEN** execave renders the effective config from `/home/user/alt.toml`

#### Scenario: Global CLI rule flags apply to run
- **WHEN** the user runs `execave --fs rw:/tmp/work run -- ls /tmp/work`
- **THEN** execave includes the CLI fs rule when loading config for run

#### Scenario: Global CLI rule flags apply to monitor
- **WHEN** the user runs `execave --fs rw:/tmp/work monitor -- ls /tmp/work`
- **THEN** execave includes the CLI fs rule when loading config for monitor

#### Scenario: Global CLI rule flags apply to config show
- **WHEN** the user runs `execave --fs rw:/tmp/work config show`
- **THEN** execave includes the CLI fs rule in the effective config output

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
- **WHEN** the user runs `execave monitor --show-allowed --no-sandbox --output - -- true`
- **THEN** monitor mode runs with those options applied

#### Scenario: Monitor flags rejected on run command
- **WHEN** the user runs `execave run --show-allowed -- true`
- **THEN** execave exits with a CLI error indicating the flag is unknown for `run`

### Requirement: CLI rule flags

The CLI SHALL expose repeatable global flags `--fs`, `--net`, `--syscall`, `--env`, and `--extends` as `StringArray` flags on the root command. Each flag occurrence adds one rule string. These flags SHALL be available to all subcommands: `run` (implicit and explicit), `monitor`, and `config show`.

#### Scenario: --fs flag accepted on implicit run

- **WHEN** the user runs `execave --fs ro:/usr -- ls`
- **THEN** execave accepts the flag and includes the fs rule in the sandbox config

#### Scenario: --net flag accepted on explicit run

- **WHEN** the user runs `execave --net http:example.com:443 run -- curl https://example.com`
- **THEN** execave accepts the flag and includes the net rule in the sandbox config

#### Scenario: --syscall flag accepted on monitor

- **WHEN** the user runs `execave --syscall allow:bpf monitor -- true`
- **THEN** execave accepts the flag and includes the syscall rule in the sandbox config

#### Scenario: --env flag accepted on implicit run

- **WHEN** the user runs `execave --env pass:HOME -- env`
- **THEN** execave accepts the flag and includes the env rule in the sandbox config

#### Scenario: --extends flag accepted on implicit run

- **WHEN** the user runs `execave --extends base.toml -- ls`
- **THEN** execave accepts the flag and includes the extends path in config loading

#### Scenario: Multiple --fs flags accumulate

- **WHEN** the user runs `execave --fs ro:/usr --fs ro:/lib -- ls`
- **THEN** execave includes both fs rules in the sandbox config

#### Scenario: CLI rule flags accepted on config show

- **WHEN** the user runs `execave --fs rw:/tmp config show`
- **THEN** execave accepts the flag and the effective config output includes the CLI rule

### Requirement: --no-config flag

The CLI SHALL expose a `--no-config` boolean global flag on the root command. When set, no config file SHALL be loaded. `--no-config` and `--config` (when explicitly set by the user) SHALL be mutually exclusive — specifying both SHALL cause execave to exit with an error.

#### Scenario: --no-config skips config file

- **WHEN** the user runs `execave --no-config --fs ro:/usr -- ls`
- **THEN** execave runs without loading any config file

#### Scenario: --no-config with --config is an error

- **WHEN** the user runs `execave --no-config --config app.toml -- ls`
- **THEN** execave exits with an error indicating the flags are mutually exclusive

#### Scenario: --no-config without any rules runs with empty policy

- **WHEN** the user runs `execave --no-config -- ls`
- **THEN** execave runs with an empty sandbox policy (default-deny everything)
