## MODIFIED Use Cases

### Use Case: Edit config alongside the access log

The user edits their TOML config file in an external editor and runs execave with monitoring to observe the access log, adjusting rules between runs.

- **GIVEN** a config file containing rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **WHEN** the process exits and the text log is printed to stderr
- **THEN** the user reviews denied entries in the text log
- **AND** edits the config file in their editor to adjust rules
- **AND** re-runs `execave --monitor -- ls /usr/lib` to verify

### Use Case: Invalid config rejected on start or save

The user sees a validation error when attempting to run with a config that contains invalid TOML or invalid rules.

- **GIVEN** a config file containing `rules = ["badprefix:something"]`
- **WHEN** the user runs `execave --monitor -- ls /usr/lib`
- **THEN** execave exits with an error containing "unknown resource type"
- **AND** no sandbox is started

## REMOVED Use Cases

### Use Case: Save edited config to disk
**Reason**: Web UI removed. Config editing is done in an external editor; saving is handled by the editor.
**Migration**: Edit the config file directly with any text editor.

### Use Case: Revert config to last-saved
**Reason**: Web UI removed. No in-memory draft to revert.
**Migration**: Use editor undo or version control to revert config changes.

### Use Case: Modified indicator shows unsaved changes
**Reason**: Web UI removed. No textarea or modified indicator.
**Migration**: Editor handles modified state natively.

### Use Case: Access token required for all web UI requests
**Reason**: Web UI removed. No HTTP server to authenticate.
**Migration**: No action needed.

### Use Case: Config editor syncs on SSE reconnect
**Reason**: Web UI removed. No SSE or browser-based editing.
**Migration**: No action needed.

### Use Case: Browser auto-opened to monitor URL
**Reason**: Web UI removed. No browser to open.
**Migration**: Use `--monitor` for stderr output or `--monitor=<file>` for file output.

### Use Case: Start a run from the web UI
**Reason**: Web UI removed. Runs are started from the CLI.
**Migration**: Re-run `execave --monitor -- <command>` from the terminal.

### Use Case: Stop a running process from the web UI
**Reason**: Web UI removed. Processes are stopped with Ctrl-C.
**Migration**: Send SIGINT (Ctrl-C) to stop the running process.

### Use Case: Restart replaces the active run
**Reason**: Web UI removed. No in-process restart.
**Migration**: Ctrl-C the running process, then re-run from the terminal.

### Use Case: Button states update in real-time
**Reason**: Web UI removed. No browser UI with buttons.
**Migration**: No action needed.

### Use Case: Access log clears on new run session
**Reason**: Web UI removed. Each CLI run produces its own text log output.
**Migration**: Each `execave --monitor` invocation starts fresh.

## RENAMED Use Cases

- FROM: Edit config alongside the access log
  TO: Edit config and re-run with monitor
- FROM: Invalid config rejected on start or save
  TO: Invalid config rejected on start
