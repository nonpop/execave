## ADDED Requirements

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

- **WHEN** ParseRules is called with `["fs:rw:/home/user"]` and configPath `/home/user/execave.toml`
- **THEN** it returns an error containing "config file must not be writable"

#### Scenario: Empty rules produce empty Config

- **WHEN** ParseRules is called with an empty slice `[]`
- **THEN** it returns a Config with no FS rules and no net rules

#### Scenario: Non-absolute configPath panics

- **WHEN** ParseRules is called with a configPath that is not an absolute path (e.g., `"execave.toml"`)
- **THEN** ParseRules panics

### Requirement: Load delegates to ParseRules

`config.Load` SHALL produce identical results to calling ParseRules with the same rule strings, configDir, configPath, and managedPaths. Load SHALL remain the file-based entry point; ParseRules SHALL be the non-I/O entry point.

#### Scenario: Load and ParseRules produce identical Config

- **WHEN** a TOML file contains `rules = ["fs:ro:/usr/bin", "net:https:example.com:443"]`
- **AND** Load is called with that file path
- **AND** ParseRules is called with the same raw rules, configDir derived from the file, the absolute file path, and the same managedPaths
- **THEN** both return equivalent Config structs (same FSRules, NetRules, and ManagedPaths)
