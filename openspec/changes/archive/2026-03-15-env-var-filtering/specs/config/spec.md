## ADDED Requirements

### Requirement: Env section in config file format

The config file SHALL accept an optional top-level `env` array of strings. Each string SHALL be parsed as an env rule. Unknown or malformed env rule bodies SHALL cause Load to return an error.

#### Scenario: Valid config with env rules

- **WHEN** config contains:
  ```toml
  env = ["pass:HOME", "pass:PATH"]
  ```
- **THEN** Load returns a config with 2 env rules

#### Scenario: Empty env section

- **WHEN** config contains:
  ```toml
  env = []
  ```
- **THEN** Load returns a config with no env rules

#### Scenario: Invalid env rule rejected at config load

- **WHEN** config contains:
  ```toml
  env = ["ro:HOME"]
  ```
- **THEN** Load returns an error containing "invalid action"

#### Scenario: Duplicate env rule rejected at config load

- **WHEN** config contains:
  ```toml
  env = ["pass:HOME", "pass:HOME"]
  ```
- **THEN** Load returns an error containing "duplicate env rule"

### Requirement: ParseTOML includes env section

`ParseTOML` SHALL unmarshal and validate the `env` key in addition to `fs`, `net`, and `syscall`.

#### Scenario: Valid env rules parsed from bytes

- **WHEN** ParseTOML is called with bytes containing:
  ```toml
  env = ["pass:HOME"]
  ```
- **THEN** it returns a Config with 1 env rule

## MODIFIED Requirements

### Requirement: Config file format

The config file SHALL be valid TOML with optional top-level array keys: `fs`, `net`, `syscall`, and `env` of strings. Rule strings within each section omit the resource-type prefix — the section determines the type. All four keys are optional; omitting a key means no rules of that type. Unknown or malformed rule bodies SHALL cause Load to return an error.

Within `fs`: `ro`, `rw`, `none` prefixes are access rules. Within `net`: `http`, `none` prefixes are access rules. Within `syscall`: `allow` is the only valid action. Within `env`: `pass` is the only valid action.

#### Scenario: Valid config with fs and net rules

- **WHEN** config contains:
  ```toml
  fs = ["ro:/usr/bin"]

  net = ["http:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Empty config (no sections)

- **WHEN** config contains no `fs`, `net`, `syscall`, or `env` keys
- **THEN** Load returns a config with no FS rules and no net rules

#### Scenario: Invalid rule rejected at config load

- **WHEN** config contains:
  ```toml
  net = ["http:example.com"]
  ```
  (missing port segment)
- **THEN** Load returns an error containing "malformed rule"

#### Scenario: Config with comments

- **WHEN** config contains TOML line comments (`#`) and inline comments within the config
- **THEN** Load parses successfully, ignoring all comments

#### Scenario: Config with trailing comma

- **WHEN** config contains a `rules` array with a trailing comma after the last element
- **THEN** Load parses successfully

#### Scenario: fs:nolog rule rejected

- **WHEN** config contains:
  ```toml
  fs = ["nolog:/usr/bin"]
  ```
- **THEN** Load returns an error (unknown rule prefix)

#### Scenario: net:nolog rule rejected

- **WHEN** config contains:
  ```toml
  net = ["nolog:*.example.com:*"]
  ```
- **THEN** Load returns an error (unknown rule prefix)

#### Scenario: syscall:nolog rule rejected

- **WHEN** config contains:
  ```toml
  syscall = ["nolog:ptrace"]
  ```
- **THEN** Load returns an error (unknown action)

### Requirement: Effective config output format and provenance

Effective config output SHALL be TOML with typed sections (`fs`, `net`, `syscall`, `env`) and SHALL include source-path provenance as comment lines for emitted rules.

#### Scenario: Output contains typed sections

- **WHEN** `config show` succeeds
- **THEN** stdout contains TOML arrays for configured sections (`fs`, `net`, `syscall`, and/or `env`) using rule bodies consistent with current config format

#### Scenario: Output includes source comments for each emitted rule

- **WHEN** `config show` emits a rule originating from layered config files
- **THEN** the emitted TOML includes one or more comment lines indicating source file path provenance adjacent to that rule
