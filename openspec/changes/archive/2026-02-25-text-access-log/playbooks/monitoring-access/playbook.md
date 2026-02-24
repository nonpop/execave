## ADDED Use Cases

### Use Case: Write access log to file

The user writes the access log to a file for viewing outside the browser, useful when TUI apps cover the terminal or when no browser is available.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=access.log -- vim src/main.go`
- **AND** the sandboxed command accesses files
- **THEN** `access.log` is created in the current directory
- **AND** entries are written to the file as they occur (tailable with `tail -f access.log`)
- **AND** each line contains result, operation, target path (shortened), and matched rule
- **AND** by default only DENY and UNKNOWN entries are written (OK entries are hidden)
- **AND** entries matching nolog rules are hidden by default
- **AND** filesystem paths are shortened the same way as in the web UI (relative to config dir, or `~/` form)

### Use Case: Write access log to stderr after process exits

The user writes the access log to stderr, which is buffered until the sandboxed process exits to avoid interleaving with the command's output.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=- -- ls /usr/lib`
- **AND** the sandboxed command exits
- **THEN** the accumulated access log entries are printed to stderr after the process exits
- **AND** by default only DENY and UNKNOWN entries are shown

### Use Case: Show allowed entries in text log

The user includes OK entries in the text log output using the `--show-allowed` flag.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=access.log --show-allowed -- ls /usr/lib`
- **THEN** `access.log` contains both OK and DENY/UNKNOWN entries

### Use Case: Show nolog entries in text log

The user includes entries suppressed by nolog rules using the `--show-nolog` flag.

- **GIVEN** a config with rules `fs:ro:/home/user/project` and `fs:nolog:/home/user/project/cache`
- **WHEN** the user runs `execave --monitor=access.log --show-nolog -- myapp`
- **THEN** `access.log` contains entries for paths under `/home/user/project/cache` that would normally be hidden by the nolog rule

### Use Case: Filter flags set initial web UI checkbox state

The user uses `--show-allowed` and `--show-nolog` with the web UI to change the initial filter state.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:nolog:/usr/lib`
- **WHEN** the user runs `execave --monitor --show-allowed --show-nolog -- ls /usr/lib`
- **AND** opens the web UI in a browser
- **THEN** the "Denied only" checkbox is unchecked (showing OK entries)
- **AND** the "Apply nolog rules" checkbox is unchecked (showing nolog entries)
- **AND** the user can still toggle both checkboxes interactively

### Use Case: Text log applies both filters independently

Both the denied-only and nolog filters operate independently in text log output, same as in the web UI.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `fs:nolog:/usr/lib`
- **WHEN** the user runs `execave --monitor=access.log --show-allowed -- ls /usr/lib /home/user/project`
- **THEN** `access.log` contains OK entries for `/home/user/project` (passes both filters)
- **AND** `access.log` does not contain entries for `/usr/lib` (passes mode filter but blocked by nolog)

### Use Case: Text log survives SIGINT

The user interrupts a long-running command and the text log contains all entries logged before the signal.

- **GIVEN** a config with rules `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=access.log -- long-running-command`
- **AND** sends SIGINT (Ctrl-C) while the command is running
- **THEN** `access.log` contains entries for all operations that occurred before the signal
- **AND** execave exits with the command's exit code
