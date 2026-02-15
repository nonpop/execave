# Iterating Config — Restarting sandboxed runs to observe access patterns

## Purpose

The user starts a monitored run via the web UI, observes the access log, then restarts the process to re-observe after adjusting their approach. This is the foundation for the interactive config editing loop.

## Use Cases

### Use Case: Start a run from the web UI

The user starts a monitored sandbox run from the web UI after the initial CLI-launched run has exited.

- **GIVEN** a config with rule `fs:ro:/usr/lib`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the initial run has exited
- **WHEN** the user clicks the "Start" button in the web UI
- **THEN** a new monitored sandbox run starts with the same command and config
- **AND** the access log is cleared and shows entries from the new run
- **AND** the run status shows the process as running

### Use Case: Stop a running process from the web UI

The user stops a long-running sandboxed process from the web UI without killing the monitor.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor=9876 -- long-running-command`
- **AND** the process is running
- **WHEN** the user clicks the stop button in the web UI
- **THEN** the sandboxed process is terminated
- **AND** the run status shows the process as exited
- **AND** the web UI remains accessible with the access log entries from the run

### Use Case: Restart replaces the active run

When a process is running, the button shows "Restart" instead of "Start". Clicking it stops the active run and starts a new one.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor=9876 -- long-running-command`
- **AND** the process is running
- **WHEN** the user clicks the "Restart" button in the web UI
- **THEN** the active process is stopped
- **AND** a new run starts with a fresh access log
- **AND** entries from the previous run are no longer visible
