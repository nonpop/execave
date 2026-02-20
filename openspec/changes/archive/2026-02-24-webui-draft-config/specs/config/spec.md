# Config Capability — Delta

## ADDED Requirements

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
