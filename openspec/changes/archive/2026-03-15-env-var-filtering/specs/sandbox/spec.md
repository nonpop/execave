## ADDED Requirements

### Requirement: Default-deny environment

BuildBwrapArgs SHALL always include `--clearenv` so that no host environment variables are visible inside the sandbox by default. For each env rule in the config, if the variable is present in the host environment, BuildBwrapArgs SHALL append `--setenv KEY VALUE`. Variables listed in env rules but absent from the host environment are silently skipped.

#### Scenario: Default-deny: no host vars without rules

- **WHEN** config contains no `env` rules
- **THEN** BuildBwrapArgs includes `--clearenv`
- **AND** BuildBwrapArgs includes no `--setenv` flags

#### Scenario: Passed variable injected

- **WHEN** config contains `env:pass:HOME`
- **AND** host environment has `HOME=/home/user`
- **THEN** BuildBwrapArgs includes `--clearenv`
- **AND** BuildBwrapArgs includes `--setenv HOME /home/user`

#### Scenario: Multiple passed variables injected

- **WHEN** config contains `env:pass:HOME` and `env:pass:PATH`
- **AND** host environment has `HOME=/home/user` and `PATH=/usr/bin`
- **THEN** BuildBwrapArgs includes `--setenv HOME /home/user` and `--setenv PATH /usr/bin`

#### Scenario: Absent host variable not injected

- **WHEN** config contains `env:pass:MISSING_VAR`
- **AND** host environment does not contain `MISSING_VAR`
- **THEN** BuildBwrapArgs includes `--clearenv`
- **AND** BuildBwrapArgs includes no `--setenv MISSING_VAR` flag
