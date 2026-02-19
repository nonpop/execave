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

### Use Case: View rules alongside the access log

The user views their config rules in the web UI while observing access log entries, so they can understand which rules govern which accesses without switching to their editor.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **WHEN** the user opens the web UI
- **THEN** the page displays the rules `fs:ro:/usr/lib` and `fs:rw:/tmp` in a rules pane
- **AND** the access log entries are displayed alongside in a separate pane

### Use Case: Rules update after restarting execave with a new config

The user edits their config, restarts execave, and the browser tab automatically shows the updated rules without a manual page refresh.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the web UI is open in a browser tab showing those rules
- **WHEN** the user stops execave, adds rule `net:allow:example.com:443`, and restarts execave on the same port
- **THEN** the browser tab reconnects and the rules pane displays `fs:ro:/usr/lib`, `fs:rw:/tmp`, and `net:allow:example.com:443`
- **AND** the previously displayed rules are replaced (no stale rules shown)

### Use Case: Hover a rule to see matching log entries

The user hovers over a rule to see which access log entries it matched, making it easy to understand what a rule governs.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the access log contains entries matched by `fs:ro:/usr/lib`
- **WHEN** the user hovers over the rule `fs:ro:/usr/lib` in the rules pane
- **THEN** the log entries whose matched rule is `fs:ro:/usr/lib` are highlighted
- **AND** log entries matched by other rules are not highlighted

### Use Case: Hover a log entry to see its matched rule

The user hovers over an access log entry to see which rule allowed or denied it.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the access log contains an entry matched by `fs:ro:/usr/lib`
- **WHEN** the user hovers over that log entry
- **THEN** the rule `fs:ro:/usr/lib` is highlighted in the rules pane
- **AND** other rules are not highlighted

### Use Case: Button states update in real-time

The user sees button labels and disabled states update automatically as the run status changes, without refreshing the page.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor=9876 -- long-running-command`
- **AND** the process is running
- **AND** the web UI shows a "Restart" button and an enabled "Stop" button
- **WHEN** the process exits
- **THEN** the "Restart" button label changes to "Start" without page refresh
- **AND** the "Stop" button becomes disabled without page refresh

### Use Case: Access log clears on new run session

When a new run starts, the browser's access log table clears and shows entries from the new run, without a page refresh.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor=9876 -- ls /home/user/data`
- **AND** the initial run has exited
- **AND** the access log table shows entries from the initial run
- **WHEN** the user starts a new run
- **THEN** the access log table in the browser is cleared without page refresh
- **AND** entries from the new run appear in real-time
