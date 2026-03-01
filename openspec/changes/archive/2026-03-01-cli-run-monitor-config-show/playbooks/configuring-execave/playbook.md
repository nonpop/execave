## MODIFIED Use Cases

### Use Case: Custom config path via `--config`

The user stores the config file at a non-default location and points execave to it with the global `--config` flag.

- **GIVEN** a valid config file at `/home/user/configs/execave.toml`
- **WHEN** the user runs `execave --config /home/user/configs/execave.toml run -- ls`
- **THEN** the system reads configuration from `/home/user/configs/execave.toml`

## ADDED Use Cases

### Use Case: Explicit run command and implicit run are equivalent
The user can invoke sandboxed execution explicitly with `run` or implicitly by providing a command without a subcommand.

- **GIVEN** a file `./execave.toml` with valid rules
- **WHEN** the user runs `execave run -- ls`
- **THEN** the command runs in the sandbox with the configured rules
- **AND** running `execave -- ls` produces equivalent sandbox behavior

### Use Case: Show effective config as TOML
The user inspects the final merged config to validate layered config composition before running commands.

- **GIVEN** a valid layered config rooted at `./execave.toml`
- **WHEN** the user runs `execave config show`
- **THEN** execave prints TOML with `fs`, `net`, and `syscall` sections representing effective merged rules
- **AND** emitted rules include source provenance as TOML comments
