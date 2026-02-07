# Config Capability

## Purpose

The config capability handles configuration file parsing, validation, and rule management for the execave sandbox. It defines how the system reads configuration, validates rule syntax, normalizes paths, and enforces security constraints to prevent privilege escalation.

## Requirements

### Requirement: Config file location

The system SHALL read configuration from `./execave.json` in the current working directory by default. The config path MAY be overridden via the `--config` CLI flag.

#### Scenario: Default config location
- **WHEN** user runs `execave -- <command>` without `--config` flag
- **THEN** system reads configuration from `./execave.json`

#### Scenario: Custom config location
- **WHEN** user runs `execave --config /path/to/config.json -- <command>`
- **THEN** system reads configuration from `/path/to/config.json`

#### Scenario: Config file not found
- **WHEN** the config file does not exist at the expected path
- **THEN** system exits with error and displays message indicating missing config file

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
