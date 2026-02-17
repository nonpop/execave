## ADDED Use Cases

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

## MODIFIED Use Cases

### Use Case: Default config location (`./execave.toml`)

The user places the config file in the current working directory with the default name. Execave finds it automatically without any flags.

- **GIVEN** a file `./execave.toml` with valid rules
- **WHEN** the user runs `execave -- ls`
- **THEN** the system reads configuration from `./execave.toml`
- **AND** the command runs in the sandbox with the configured rules

### Use Case: Missing config file shows error

The user runs execave without a config file at the expected path. The system exits with a clear error message.

- **GIVEN** no `./execave.toml` file exists in the current directory
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the config file was not found

### Use Case: Config file explicitly writable rejected

The user has a config where a rule explicitly grants read-write access to the config file itself. The system rejects this to prevent sandboxed processes from modifying the config and escalating privileges in future runs.

- **GIVEN** a config file at `/home/user/project/execave.toml` with rule `fs:rw:/home/user/project/execave.toml`
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- ls`
- **THEN** the system exits with an error indicating the config file must not be explicitly writable
