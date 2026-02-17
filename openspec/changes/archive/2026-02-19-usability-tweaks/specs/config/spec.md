## MODIFIED Requirements

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
