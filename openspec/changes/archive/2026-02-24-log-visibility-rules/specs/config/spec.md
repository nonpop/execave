## MODIFIED Requirements

### Requirement: Config file format

The config file SHALL be valid TOML containing a `rules` array of strings. Rules are routed by resource prefix: `fs:` rules are parsed by the FS rules engine, `net:` rules are parsed by the net rules engine. Within each prefix, the action/permission determines whether the rule is an access rule or a log rule: `fs:ro`, `fs:rw`, `fs:none` are access rules; `fs:log`, `fs:nolog` are log rules; `net:https`, `net:http`, `net:none` are access rules; `net:log`, `net:nolog` are log rules. Unknown prefixes or malformed rules SHALL cause Load to return an error.

#### Scenario: Valid config with fs and net rules

- **WHEN** config contains:
  ```toml
  rules = ["fs:ro:/usr/bin", "net:https:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Valid config with log rules

- **WHEN** config contains:
  ```toml
  rules = ["fs:ro:/usr/bin", "fs:nolog:/usr/bin", "net:https:api.example.com:443", "net:nolog:*.example.com:*"]
  ```
- **THEN** Load returns a config with 1 FS access rule, 1 FS log rule, 1 net access rule, and 1 net log rule

#### Scenario: Empty rules array

- **WHEN** config contains `rules = []`
- **THEN** Load returns a config with no FS rules, no net rules, no FS log rules, and no net log rules

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

`config.ParseRules` SHALL accept raw rule strings and return a validated `*Config` with the same guarantees as `config.Load`. It SHALL apply all validation: duplicate path detection, config writability check, managed path rejection, net rule identity/port-pattern checks, log rule duplicate path detection, and log rule duplicate identity detection.

#### Scenario: Valid fs and net rules parsed from strings

- **WHEN** ParseRules is called with `["fs:ro:/usr/bin", "net:https:api.example.com:443"]`, a valid configDir, configPath, and nil managedPaths
- **THEN** it returns a Config with 1 FS rule (read-only, path `/usr/bin`) and 1 net rule

#### Scenario: Log rules parsed from strings

- **WHEN** ParseRules is called with `["fs:nolog:/usr/lib", "net:nolog:*.example.com:*"]`, a valid configDir, configPath, and nil managedPaths
- **THEN** it returns a Config with 1 FS log rule and 1 net log rule

#### Scenario: Tilde expansion in fs rule path

- **WHEN** ParseRules is called with `["fs:rw:~/projects"]` and a valid configDir
- **THEN** the returned FS rule path is the absolute home directory path with `/projects` appended

#### Scenario: Tilde expansion in fs log rule path

- **WHEN** ParseRules is called with `["fs:nolog:~/projects"]` and a valid configDir
- **THEN** the returned FS log rule path is the absolute home directory path with `/projects` appended

#### Scenario: Relative path resolved against configDir

- **WHEN** ParseRules is called with `["fs:ro:data"]` and configDir `/home/user/myproject`
- **THEN** the returned FS rule path is `/home/user/myproject/data`

#### Scenario: Invalid rule rejected

- **WHEN** ParseRules is called with `["badprefix:something"]`
- **THEN** it returns an error containing "unknown resource type"

#### Scenario: Duplicate fs paths rejected

- **WHEN** ParseRules is called with `["fs:ro:/usr/bin", "fs:rw:/usr/bin"]`
- **THEN** it returns an error containing "duplicate path"

#### Scenario: Duplicate fs log rule paths rejected

- **WHEN** ParseRules is called with `["fs:nolog:/usr/bin", "fs:log:/usr/bin"]`
- **THEN** it returns an error containing "duplicate path"

#### Scenario: Managed path rejected

- **WHEN** ParseRules is called with `["fs:ro:/dev"]` and managedPaths `["/dev"]`
- **THEN** it returns an error containing "managed path"

#### Scenario: Config writability rejected

- **WHEN** ParseRules is called with `["fs:rw:/home/user/execave.toml"]` and configPath `/home/user/execave.toml`
- **THEN** it returns an error containing "config file must not be writable"

#### Scenario: Empty rules produce empty Config

- **WHEN** ParseRules is called with an empty slice `[]`
- **THEN** it returns a Config with no FS rules, no net rules, no FS log rules, and no net log rules

#### Scenario: Non-absolute configPath panics

- **WHEN** ParseRules is called with a configPath that is not an absolute path (e.g., `"execave.toml"`)
- **THEN** ParseRules panics
