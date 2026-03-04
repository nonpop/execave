## MODIFIED Requirements

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

### Requirement: Parse rules from in-memory strings

`config.ParseRules` SHALL accept raw rule strings and return a validated `*Config` with the same guarantees as `config.Load`. It SHALL apply all validation: duplicate path detection, config writability check, managed path rejection, and net rule identity/port-pattern checks.

#### Scenario: Valid fs and net rules parsed from strings

- **WHEN** ParseRules is called with `["fs:ro:/usr/bin", "net:http:api.example.com:443"]`, a valid configDir, configPath, and nil managedPaths
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

#### Scenario: fs:nolog rule rejected by ParseRules

- **WHEN** ParseRules is called with `["fs:nolog:/usr/lib"]`
- **THEN** it returns an error (unknown rule prefix)

#### Scenario: net:nolog rule rejected by ParseRules

- **WHEN** ParseRules is called with `["net:nolog:*.example.com:*"]`
- **THEN** it returns an error (unknown rule prefix)
