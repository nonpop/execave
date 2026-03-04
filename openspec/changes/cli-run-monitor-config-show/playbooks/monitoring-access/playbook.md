## MODIFIED Use Cases

### Use Case: View access log in text output

The user runs monitor mode to view access log entries in text format on stderr or in a file, with operation type, target, result, and matched rule columns. Filesystem target paths are displayed in shortened form. By default, only DENY and UNKNOWN entries are shown; the user can include OK entries with `--show-allowed`.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave monitor --output - -- ls /usr/lib`
- **THEN** the access log is printed to stderr after the process exits
- **AND** by default only `DENY` and `UNKNOWN` entries are shown
- **AND** with `--show-allowed`, all entries including `OK` are shown
- **AND** paths under the config directory are shortened to relative form (e.g., `src/main.go` instead of `/home/user/project/src/main.go`)
- **AND** paths under the home directory but outside the config directory are shortened with `~` (e.g., `~/.ssh/id_rsa` instead of `/home/user/.ssh/id_rsa`)
- **AND** paths outside the home directory are shown as absolute (e.g., `/usr/lib/libc.so`)
- **AND** rules are shown verbatim as written in the config (e.g., `fs:rw:~/project`)

### Use Case: Real-time streaming to file

The user writes the access log to a file and tails it in real time as the monitored command runs.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave monitor --output access.log -- long-running-command`
- **AND** runs `tail -f access.log` in another terminal
- **THEN** new log entries appear in the tail output while the command is still running

## ADDED Use Cases

### Use Case: Monitor-specific flags are scoped to monitor command
The user uses monitor-only behavior through the `monitor` subcommand, while root flags remain global.

- **GIVEN** a valid config file
- **WHEN** the user runs `execave --config ./execave.toml monitor --show-allowed --show-nolog --no-sandbox --output monitor.log -- command`
- **THEN** monitor mode runs with those flags applied
- **AND** `--config` is accepted before the subcommand as a global option
