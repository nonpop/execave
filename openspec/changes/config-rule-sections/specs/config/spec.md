## MODIFIED Requirements

### Requirement: Config file format

The config file SHALL be valid TOML with optional top-level array keys: `fs`, `net`, and `syscall` of strings. Rule strings within each section omit the resource-type prefix — the section determines the type. All three keys are optional; omitting a key means no rules of that type. Unknown or malformed rule bodies SHALL cause Load to return an error.

Within `fs`: `ro`, `rw`, `none` prefixes are access rules; `log`, `nolog` prefixes are log rules. Within `net`: `http`, `none` prefixes are access rules; `log`, `nolog` prefixes are log rules. Within `syscall`: `allow` and `nolog` are the only valid actions.

#### Scenario: Valid config with fs and net rules

- **WHEN** config contains:
  ```toml
  fs = ["ro:/usr/bin"]

  net = ["http:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Valid config with log rules

- **WHEN** config contains:
  ```toml
  fs = ["ro:/usr/bin", "nolog:/usr/bin"]

  net = ["http:api.example.com:443", "nolog:*.example.com:*"]
  ```
- **THEN** Load returns a config with 1 FS access rule, 1 FS log rule, 1 net access rule, and 1 net log rule

#### Scenario: Empty config (no sections)

- **WHEN** config contains no `fs`, `net`, or `syscall` keys
- **THEN** Load returns a config with no FS rules, no net rules, no FS log rules, and no net log rules

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

### Requirement: Parse TOML from bytes

`config.ParseTOML` SHALL accept raw TOML bytes, a configDir, a configPath, and managedPaths, and return a validated `*Config`. It SHALL unmarshal the `fs`, `net`, and `syscall` keys, prepend the appropriate resource-type prefix to each rule string, and delegate to `ParseRules`. It SHALL apply all validation that `Load` applies. `Load` SHALL delegate to `ParseTOML` internally, so that `Load` and `ParseTOML` produce identical results for the same input.

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

### Requirement: Load delegates to ParseRules

`config.Load` SHALL produce identical results to calling ParseRules with the equivalent prefixed rule strings (resource-type prefix prepended), configDir, configPath, and managedPaths. Load SHALL remain the file-based entry point; ParseRules SHALL be the non-I/O entry point accepting prefixed rule strings.

#### Scenario: Load and ParseRules produce identical Config
- **WHEN** a TOML file contains `fs = ["ro:/usr/bin"]` and `net = ["http:example.com:443"]`
- **AND** Load is called with that file path
- **AND** ParseRules is called with `["fs:ro:/usr/bin", "net:http:example.com:443"]`, configDir derived from the file, the absolute file path, and the same managedPaths
- **THEN** both return equivalent Config structs (same FSRules, NetRules, and ManagedPaths)

## REMOVED Requirements

### Requirement: Unknown resource type rejected

**Reason**: With the sectioned format, rule strings no longer carry a resource-type prefix; the section (`fs`, `net`, `syscall`) determines the type. The concept of an "unknown resource type" no longer applies at the config-file level. Invalid permission/action strings within a section are still rejected by the existing action-parsing logic in fsrules/netrules.

**Migration**: The `ParseRules` API still accepts prefixed strings and still rejects unknown prefixes with "unknown resource type" — this is unchanged. Only `ParseTOML`/`Load` (the file-based path) no longer routes by prefix.
