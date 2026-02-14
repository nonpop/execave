# Config Capability

## Purpose

The config capability loads and parses the execave configuration file. It reads JSON, routes rules to the appropriate engine by resource prefix (`fs:` or `net:`), and rejects unrecognized or malformed input at load time.

## Requirements

### Requirement: Config file location

`config.Load` SHALL accept an explicit file path. If the file does not exist, it SHALL return an error.

#### Scenario: Config file not found
- **WHEN** the config file does not exist at the given path
- **THEN** Load returns an error containing "config file not found"

### Requirement: Config file format

The config file SHALL be valid JSON containing a `rules` array of strings. Rules are routed by resource prefix: `fs:` rules are parsed by the FS rules engine, `net:` rules are parsed by the net rules engine. Unknown prefixes or malformed rules SHALL cause Load to return an error.

#### Scenario: Valid config with fs and net rules
- **WHEN** config contains `{"rules": ["fs:ro:/usr/bin", "net:https:api.anthropic.com:443"]}`
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Empty rules array
- **WHEN** config contains `{"rules": []}`
- **THEN** Load returns a config with no FS rules and no net rules

#### Scenario: Unknown resource type
- **WHEN** config contains rule `dns:allow:example.com`
- **THEN** Load returns an error containing "unknown resource type"

#### Scenario: Invalid rule rejected at config load
- **WHEN** config contains rule `net:https:example.com` (missing port segment)
- **THEN** Load returns an error containing "malformed rule"
