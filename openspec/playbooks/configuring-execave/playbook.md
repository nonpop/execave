# Configuring Execave — Setting up and validating configuration

## Purpose

The user creates and manages the execave configuration file. The system validates all rules before running any command, catching syntax errors, conflicts, and security violations at config load time rather than at runtime.

## Use Cases

### Use Case: Default config location (`./execave.toml`)

The user places the config file in the current working directory with the default name. Execave finds it automatically without any flags.

- **GIVEN** a file `./execave.toml` with valid rules
- **WHEN** the user runs `execave -- ls`
- **THEN** the system reads configuration from `./execave.toml`
- **AND** the command runs in the sandbox with the configured rules

### Use Case: Custom config path via `--config`

The user stores the config file at a non-default location and points execave to it with the `--config` flag.

- **GIVEN** a valid config file at `/home/user/configs/sandbox.json`
- **WHEN** the user runs `execave --config /home/user/configs/sandbox.json -- ls`
- **THEN** the system reads configuration from `/home/user/configs/sandbox.json`

### Use Case: Missing config file shows error

The user runs execave without a config file at the expected path. The system exits with a clear error message.

- **GIVEN** no `./execave.toml` file exists in the current directory
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the config file was not found

### Use Case: Invalid rule syntax rejected before execution

The user has a config with a malformed rule. The system catches the error at config load time and exits before running any command.

- **GIVEN** a config with rule `fs:readonly:/home/user` (invalid permission type)
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the invalid rule syntax
- **AND** the command is never executed

### Use Case: Unknown resource type rejected

The user has a config with a rule using an unrecognized resource prefix. The system rejects it before running the command.

- **GIVEN** a config with rule `dns:allow:example.com`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the unknown resource type

### Use Case: Duplicate filesystem paths rejected

The user has a config where two rules target the same normalized path. The system rejects the config because duplicate paths indicate a configuration error.

- **GIVEN** a config with rules `fs:ro:/home/user` and `fs:rw:/home/user`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate path `/home/user`

### Use Case: Duplicate network rule identity rejected

The user has a config where two net rules share the same target and port pattern. The system rejects the config because the conflicting actions cannot be resolved.

- **GIVEN** a config with rules `net:https:example.com:443` and `net:none:example.com:443`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate net rule identity

### Use Case: Mixed port patterns on same target rejected

The user has a config where the same target has both a wildcard port rule and a specific port rule. The system rejects this because the interaction between wildcard and specific ports is ambiguous.

- **GIVEN** a config with rules `net:https:example.com:*` and `net:none:example.com:443`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating mixed port patterns on the same target

### Use Case: Config file with comments

The user adds comments to the TOML config file to document the purpose of each rule. The system accepts the config and applies all rules normally.

- **GIVEN** a config file `execave.toml` containing:
  ```toml
  # Sandbox for my coding agent
  rules = [
      # Project directory: full access
      "fs:rw:/home/user/project",

      # System libraries: read-only
      "fs:ro:/usr",
  ]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system reads the config, ignoring comments
- **AND** the command runs in the sandbox with the configured rules

### Use Case: Tilde expansion in filesystem rules

The user writes `~/...` paths in rules instead of full absolute paths. The system expands `~` to the user's home directory at config load time.

- **GIVEN** a config file with rule `fs:rw:~/project`
- **AND** the user's home directory is `/home/user`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system expands `~` to `/home/user` and mounts `/home/user/project` read-write in the sandbox

### Use Case: Tilde in config validation errors

The user writes a tilde path that conflicts with another rule. The error message includes the original tilde path for clarity.

- **GIVEN** a config file with rules `fs:rw:~/project` and `fs:ro:~/project`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate path `/home/user/project`

### Use Case: Config file explicitly writable rejected

The user has a config where a rule explicitly grants read-write access to the config file itself. The system rejects this to prevent sandboxed processes from modifying the config and escalating privileges in future runs.

- **GIVEN** a config file at `/home/user/project/execave.toml` with rule `fs:rw:/home/user/project/execave.toml`
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- ls`
- **THEN** the system exits with an error indicating the config file must not be explicitly writable

### Use Case: Managed paths (`/dev`, `/proc`, `/tmp`) in rules rejected

The user has a config with a rule targeting a managed path or its descendant. The system rejects it because these paths are mounted automatically by the sandbox and user rules would conflict.

- **GIVEN** a config with rule `fs:ro:/proc/self/status`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the rule targets a managed path
