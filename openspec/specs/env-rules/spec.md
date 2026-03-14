# Env Rules Capability

## Purpose

The env-rules capability handles parsing, validation, and resolution of environment variable forwarding rules. It defines the `pass:NAME` syntax, validates variable names, rejects duplicates, and resolves which host environment variables to forward into the sandbox.

## Requirements

### Requirement: Env rule syntax

The system SHALL parse each env rule body matching the pattern `pass:<name>` where `<name>` is a non-empty environment variable name. No other action prefix is valid. Invalid rules SHALL be rejected with an error.

#### Scenario: Valid pass rule

- **WHEN** parsing rule body `pass:HOME`
- **THEN** parsing succeeds with Name `HOME`

#### Scenario: Valid pass rule with underscore

- **WHEN** parsing rule body `pass:MY_VAR`
- **THEN** parsing succeeds with Name `MY_VAR`

#### Scenario: Empty name rejected

- **WHEN** parsing rule body `pass:`
- **THEN** parsing returns error containing "empty variable name"

#### Scenario: Invalid action rejected

- **WHEN** parsing rule body `allow:HOME`
- **THEN** parsing returns error containing "invalid action"

#### Scenario: Unknown action rejected

- **WHEN** parsing rule body `ro:HOME`
- **THEN** parsing returns error containing "invalid action"

#### Scenario: Missing colon rejected

- **WHEN** parsing rule body `HOME`
- **THEN** parsing returns error containing "malformed rule"

### Requirement: Canonical form

Each env rule SHALL have a canonical string form `pass:<name>` used for deduplication and display. The canonical form preserves the original variable name case.

#### Scenario: Canonical form of pass rule

- **WHEN** parsing rule body `pass:HOME`
- **THEN** Canonical() returns `pass:HOME`

### Requirement: No duplicate rules

Two env rules SHALL NOT have the same variable name. Duplicate rules SHALL be rejected with an error during validation.

#### Scenario: Duplicate variable name rejected

- **WHEN** rules contain `pass:HOME` and `pass:HOME`
- **THEN** validation returns error containing "duplicate env rule"

#### Scenario: Different variable names allowed

- **WHEN** rules contain `pass:HOME` and `pass:PATH`
- **THEN** validation succeeds

### Requirement: Resolve env vars from host environment

The resolver SHALL accept a host environment (as `[]string` in `KEY=VALUE` format) and return only those variables that have a matching `pass` rule. Variables listed in `pass` rules but absent from the host environment SHALL be silently skipped.

#### Scenario: Matching variable resolved

- **WHEN** rules contain `pass:HOME`
- **AND** host environment contains `HOME=/home/user`
- **THEN** Resolve returns `HOME=/home/user`

#### Scenario: Multiple matching variables resolved

- **WHEN** rules contain `pass:HOME` and `pass:PATH`
- **AND** host environment contains `HOME=/home/user` and `PATH=/usr/bin`
- **THEN** Resolve returns both `HOME=/home/user` and `PATH=/usr/bin`

#### Scenario: Absent host variable silently skipped

- **WHEN** rules contain `pass:HOME` and `pass:MISSING_VAR`
- **AND** host environment contains `HOME=/home/user` but not `MISSING_VAR`
- **THEN** Resolve returns only `HOME=/home/user`

#### Scenario: No rules resolves to empty

- **WHEN** rules are empty
- **AND** host environment contains `HOME=/home/user`
- **THEN** Resolve returns an empty list

#### Scenario: Host variable with empty value resolved

- **WHEN** rules contain `pass:EMPTY_VAR`
- **AND** host environment contains `EMPTY_VAR=`
- **THEN** Resolve returns `EMPTY_VAR=`

#### Scenario: Host variable without matching rule excluded

- **WHEN** rules contain `pass:HOME`
- **AND** host environment contains `HOME=/home/user` and `SECRET=abc`
- **THEN** Resolve returns only `HOME=/home/user`
