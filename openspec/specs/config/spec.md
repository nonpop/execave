# Config Capability

## Purpose

The config capability loads and parses the execave configuration file. It reads TOML, routes rules to the appropriate engine by resource prefix (`fs:` or `net:`), and rejects unrecognized or malformed input at load time.

## Requirements

### Requirement: Config file location

`config.Load` SHALL accept an explicit file path. If the file does not exist, it SHALL return an error.

#### Scenario: Config file not found
- **WHEN** the config file does not exist at the given path
- **THEN** Load returns an error containing "config file not found"

### Requirement: Config file format

The config file SHALL be valid TOML containing a `rules` array of strings. Rules are routed by resource prefix: `fs:` rules are parsed by the FS rules engine, `net:` rules are parsed by the net rules engine. Unknown prefixes or malformed rules SHALL cause Load to return an error.

#### Scenario: Valid config with fs and net rules
- **WHEN** config contains:
  ```toml
  rules = ["fs:ro:/usr/bin", "net:https:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Empty rules array
- **WHEN** config contains `rules = []`
- **THEN** Load returns a config with no FS rules and no net rules

#### Scenario: Unknown resource type
- **WHEN** config contains rule `"dns:allow:example.com"`
- **THEN** Load returns an error containing "unknown resource type"

#### Scenario: Invalid rule rejected at config load
- **WHEN** config contains rule `"net:https:example.com"` (missing port segment)
- **THEN** Load returns an error containing "malformed rule"

#### Scenario: Config with comments
- **WHEN** config contains TOML line comments (`#`) and inline comments
- **THEN** Load parses successfully, ignoring all comments

#### Scenario: Config with trailing comma
- **WHEN** config contains a rules array with a trailing comma after the last element
- **THEN** Load parses successfully

### Requirement: Parse rules from in-memory strings

`config.ParseRules` SHALL accept raw rule strings and return a validated `*Config` with the same guarantees as `config.Load`. It SHALL apply all validation: duplicate path detection, config writability check, managed path rejection, and net rule identity/port-pattern checks.

#### Scenario: Valid fs and net rules parsed from strings
- **WHEN** ParseRules is called with `["fs:ro:/usr/bin", "net:https:api.example.com:443"]`, a valid configDir, configPath, and nil managedPaths
- **THEN** it returns a Config with 1 FS rule (read-only, path `/usr/bin`) and 1 net rule

#### Scenario: Tilde expansion in fs rule path
- **WHEN** ParseRules is called with `["fs:rw:~/projects"]` and a valid configDir
- **THEN** the returned FS rule path is the absolute home directory path with `/projects` appended

#### Scenario: Relative path resolved against configDir
- **WHEN** ParseRules is called with `["fs:ro:data"]` and configDir `/home/user/myproject`
- **THEN** the returned FS rule path is `/home/user/myproject/data`

#### Scenario: Invalid rule rejected
- **WHEN** ParseRules is called with `["badprefix:something"]`
- **THEN** it returns an error containing "unknown resource type"

#### Scenario: Duplicate fs paths rejected
- **WHEN** ParseRules is called with `["fs:ro:/usr/bin", "fs:rw:/usr/bin"]`
- **THEN** it returns an error containing "duplicate path"

#### Scenario: Managed path rejected
- **WHEN** ParseRules is called with `["fs:ro:/dev"]` and managedPaths `["/dev"]`
- **THEN** it returns an error containing "managed path"

#### Scenario: Config writability rejected
- **WHEN** ParseRules is called with `["fs:rw:/home/user/execave.toml"]` and configPath `/home/user/execave.toml`
- **THEN** it returns an error containing "config file must not be writable"

#### Scenario: Empty rules produce empty Config
- **WHEN** ParseRules is called with an empty slice `[]`
- **THEN** it returns a Config with no FS rules and no net rules

#### Scenario: Non-absolute configPath panics
- **WHEN** ParseRules is called with a configPath that is not an absolute path (e.g., `"execave.toml"`)
- **THEN** ParseRules panics

### Requirement: Parse TOML from bytes

`config.ParseTOML` SHALL accept raw TOML bytes, a configDir, a configPath, and managedPaths, and return a validated `*Config`. It SHALL unmarshal the TOML, extract the `rules` array, and delegate to `ParseRules` with the same configDir, configPath, and managedPaths. It SHALL apply all validation that `Load` applies. `Load` SHALL delegate to `ParseTOML` internally, so that `Load` and `ParseTOML` produce identical results for the same input.

#### Scenario: Valid TOML parsed from bytes

- **WHEN** ParseTOML is called with bytes containing `rules = ["fs:ro:/usr/bin", "net:https:example.com:443"]`, a valid configDir, an absolute configPath, and nil managedPaths
- **THEN** it returns a Config with 1 FS rule and 1 net rule

#### Scenario: Empty TOML produces empty Config

- **WHEN** ParseTOML is called with empty bytes
- **THEN** it returns a Config with no FS rules and no net rules

#### Scenario: Invalid TOML rejected

- **WHEN** ParseTOML is called with bytes that are not valid TOML
- **THEN** it returns an error

#### Scenario: Invalid rule rejected via ParseTOML

- **WHEN** ParseTOML is called with bytes containing `rules = ["badprefix:something"]`
- **THEN** it returns an error containing "unknown resource type"

#### Scenario: ParseTOML produces identical result to Load

- **WHEN** a TOML file contains `rules = ["fs:ro:/usr/bin", "net:https:example.com:443"]`
- **AND** Load is called with that file path and managedPaths
- **AND** ParseTOML is called with the file's bytes, the file's directory, the absolute file path, and the same managedPaths
- **THEN** both return equivalent Config structs (same FSRules, NetRules, and ManagedPaths)

#### Scenario: TOML with comments parsed from bytes

- **WHEN** ParseTOML is called with bytes containing TOML comments and `rules = ["fs:ro:/usr/bin"]`
- **THEN** it returns a Config with 1 FS rule (comments are ignored)

### Requirement: Load delegates to ParseRules

`config.Load` SHALL produce identical results to calling ParseRules with the same rule strings, configDir, configPath, and managedPaths. Load SHALL remain the file-based entry point; ParseRules SHALL be the non-I/O entry point.

#### Scenario: Load and ParseRules produce identical Config
- **WHEN** a TOML file contains `rules = ["fs:ro:/usr/bin", "net:https:example.com:443"]`
- **AND** Load is called with that file path
- **AND** ParseRules is called with the same raw rules, configDir derived from the file, the absolute file path, and the same managedPaths
- **THEN** both return equivalent Config structs (same FSRules, NetRules, and ManagedPaths)
