# Config Capability

## Purpose

The config capability loads and parses the execave configuration file. It reads TOML, routes rules to the appropriate engine by section key (`fs`, `net`, `syscall`), and rejects unrecognized or malformed input at load time.

## Requirements

### Requirement: Config file location

`config.Load` SHALL accept an explicit file path. If the file does not exist, it SHALL return an error.

#### Scenario: Config file not found
- **WHEN** the config file does not exist at the given path
- **THEN** Load returns an error containing "config file not found"

### Requirement: Config file format

The config file SHALL be valid TOML with optional top-level array keys: `fs`, `net`, and `syscall` of strings. Rule strings within each section omit the resource-type prefix — the section determines the type. All three keys are optional; omitting a key means no rules of that type. Unknown or malformed rule bodies SHALL cause Load to return an error.

Within `fs`: `ro`, `rw`, `none` prefixes are access rules. Within `net`: `http`, `none` prefixes are access rules. Within `syscall`: `allow` is the only valid action.

#### Scenario: Valid config with fs and net rules

- **WHEN** config contains:
  ```toml
  fs = ["ro:/usr/bin"]

  net = ["http:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Empty config (no sections)

- **WHEN** config contains no `fs`, `net`, or `syscall` keys
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

### Requirement: Parse TOML from bytes

`config.ParseTOML` SHALL accept raw TOML bytes, a configDir, a configPath, and managedPaths, and return a validated `*Config`. It SHALL unmarshal the `fs`, `net`, and `syscall` keys and apply all validation that `Load` applies. `Load` SHALL delegate to `ParseTOML` internally, so that `Load` and `ParseTOML` produce identical results for the same input.

#### Scenario: Valid TOML parsed from bytes

- **WHEN** ParseTOML is called with bytes containing:
  ```toml
  fs = ["ro:/usr/bin"]

  net = ["http:example.com:443"]
  ```
  a valid configDir, an absolute configPath, and nil managedPaths
- **THEN** it returns a Config with 1 FS rule and 1 net rule

#### Scenario: Empty TOML produces empty Config

- **WHEN** ParseTOML is called with empty bytes
- **THEN** it returns a Config with no FS rules and no net rules

#### Scenario: Invalid TOML rejected

- **WHEN** ParseTOML is called with bytes that are not valid TOML
- **THEN** it returns an error

#### Scenario: Invalid rule rejected via ParseTOML

- **WHEN** ParseTOML is called with bytes containing:
  ```toml
  net = ["http:example.com"]
  ```
  (missing port segment)
- **THEN** it returns an error containing "malformed rule"

#### Scenario: ParseTOML produces identical result to Load

- **WHEN** a TOML file contains `fs` and `net` keys with rules
- **AND** Load is called with that file path and managedPaths
- **AND** ParseTOML is called with the file's bytes, the file's directory, the absolute file path, and the same managedPaths
- **THEN** both return equivalent Config structs (same FSRules, NetRules, and ManagedPaths)

#### Scenario: TOML with comments parsed from bytes

- **WHEN** ParseTOML is called with bytes containing TOML comments within the sections
- **THEN** it returns a Config successfully (comments are ignored)

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
