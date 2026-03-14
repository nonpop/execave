## ADDED Use Cases

### Use Case: Pass env vars via env section

The user adds an `env` section to the config to pass specific host environment variables into the sandbox.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:PATH"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the command runs successfully with HOME and PATH set from the host environment

### Use Case: Invalid env rule action rejected

The user has a config with an unrecognized action in the `env` section. The system rejects it at config load time before running any command.

- **GIVEN** a config with:
  ```toml
  env = ["ro:HOME"]
  ```
  (invalid action — only `pass` is valid for env rules)
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the invalid rule syntax
- **AND** the command is never executed

### Use Case: Duplicate env pass rule rejected

The user has a config where the same environment variable appears twice in the `env` section. The system rejects the config as a configuration error.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:HOME"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating a duplicate env rule for `HOME`

### Use Case: Show effective config includes env rules

The user inspects the effective config and sees the `env` section with source provenance comments.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:PATH"]
  ```
- **WHEN** the user runs `execave config show`
- **THEN** the output includes an `env` section listing the pass rules
- **AND** each rule includes a source provenance comment
