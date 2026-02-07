## MODIFIED Requirements

### Requirement: Config file format

The config file SHALL be valid JSON containing a `rules` array. Each rule SHALL be a string. Rules are routed by resource prefix: `fs:` rules are parsed by the FS rules engine, `net:` rules are parsed by the net rules engine. Unknown resource prefixes SHALL cause the application to exit with an error before running the command.

#### Scenario: Valid config with fs and net rules
- **WHEN** config file contains `{"rules": ["fs:ro:/usr/bin", "net:https:api.anthropic.com:443"]}`
- **THEN** sandboxed command runs successfully

#### Scenario: Empty rules array
- **WHEN** config file contains `{"rules": []}`
- **THEN** system runs with default-deny (no paths accessible, no network access)

#### Scenario: Unknown resource type
- **WHEN** config contains rule `dns:allow:example.com`
- **THEN** system exits with error indicating unknown resource type

#### Scenario: Invalid rule rejected at config load
- **WHEN** config contains rule `net:https:example.com`
- **THEN** system exits with error before running the command
