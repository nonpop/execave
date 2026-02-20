# Iterating Config — Delta

## ADDED Use Cases

### Use Case: Edit config alongside the access log

The user views and edits their raw TOML config in a textarea in the web UI while observing access log entries, so they can adjust rules without switching to an external editor.

- **GIVEN** a config file containing rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **WHEN** the user opens the web UI
- **THEN** the page displays an editable textarea containing the verbatim TOML config file (including comments)
- **AND** the access log entries are displayed alongside in a separate pane

### Use Case: Save edited config to disk

The user saves the edited config from the textarea to the original config file on disk.

- **GIVEN** a config file at `~/myproject/execave.toml` containing `rules = ["fs:ro:/usr/lib"]`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the user has edited the textarea to add `"fs:rw:/tmp"` to the rules array
- **WHEN** the user clicks the "Save" button in the web UI
- **THEN** the file `~/myproject/execave.toml` is updated with the textarea content
- **AND** the modified indicator disappears

### Use Case: Revert config to last-saved

The user discards unsaved changes in the textarea, reverting to the last-saved config content.

- **GIVEN** a config file containing `rules = ["fs:ro:/usr/lib"]`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the user has edited the textarea to add `"fs:rw:/tmp"` to the rules array
- **AND** the modified indicator is visible
- **WHEN** the user clicks the "Revert" button in the web UI
- **THEN** the textarea content is reset to the last-saved config (without `"fs:rw:/tmp"`)
- **AND** the modified indicator disappears

### Use Case: Modified indicator shows unsaved changes

The user sees a visual indicator when the textarea content differs from the last-saved config, so they know whether they have unsaved changes.

- **GIVEN** a config file containing `rules = ["fs:ro:/usr/lib"]`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the textarea shows the saved config (no modified indicator)
- **WHEN** the user edits the textarea to change a rule
- **THEN** a modified indicator appears in the web UI
- **AND** the "Revert" button becomes enabled

### Use Case: Invalid config rejected on start or save

The user sees a validation error when attempting to start a run or save a config that contains invalid TOML or invalid rules.

- **GIVEN** a valid config file
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the user has edited the textarea to contain `rules = ["badprefix:something"]`
- **WHEN** the user clicks the "Start" button in the web UI
- **THEN** the run does not start
- **AND** an error message containing "unknown resource type" is displayed in the web UI

### Use Case: Access token required for all web UI requests

Every HTTP request to the web UI server requires a valid access token, protecting against unauthorized access when the port is accidentally exposed.

- **GIVEN** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the server has printed a URL with a token to stderr (e.g., `http://127.0.0.1:54321?token=abc123`)
- **WHEN** a request is made to the server without the `?token=` query parameter
- **THEN** the server responds with 403 Forbidden
- **AND** when the same request is made with the correct `?token=abc123` parameter, the server responds normally

### Use Case: Config editor syncs on SSE reconnect

When the browser's SSE connection drops and reconnects within the same session, the config textarea is repopulated with the current server-side draft and saved state.

- **GIVEN** a config file containing `rules = ["fs:ro:/usr/lib"]`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the user has edited the textarea and started a run with the edited config
- **WHEN** the SSE connection drops and automatically reconnects
- **THEN** the textarea is repopulated with the current draft config from the server
- **AND** the modified indicator reflects whether the draft differs from the saved config

### Use Case: Browser auto-opened to monitor URL

When the user starts execave with `--monitor`, the browser is automatically opened to the monitor URL (including the access token). A `--no-open` flag disables this.

- **GIVEN** a valid config file
- **WHEN** the user runs `execave --monitor -- ls /usr/lib`
- **THEN** the server prints the full URL (with token) to stderr
- **AND** the default browser is opened to that URL

## MODIFIED Use Cases

### Use Case: Start a run from the web UI

The user starts a monitored sandbox run from the web UI after the initial CLI-launched run has exited. The run uses the config currently in the textarea.

- **GIVEN** a config with rule `fs:ro:/usr/lib`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **AND** the initial run has exited
- **AND** the user has edited the textarea to add `"fs:rw:/tmp"` to the rules
- **WHEN** the user clicks the "Start" button in the web UI
- **THEN** a new monitored sandbox run starts with the edited config (including the `fs:rw:/tmp` rule)
- **AND** the access log is cleared and shows entries from the new run
- **AND** the run status shows the process as running

### Use Case: Stop a running process from the web UI

The user stops a long-running sandboxed process from the web UI without killing the monitor.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor -- long-running-command`
- **AND** the process is running
- **WHEN** the user clicks the stop button in the web UI
- **THEN** the sandboxed process is terminated
- **AND** the run status shows the process as exited
- **AND** the web UI remains accessible with the access log entries from the run

### Use Case: Restart replaces the active run

When a process is running, the button shows "Restart" instead of "Start". Clicking it stops the active run and starts a new one using the config currently in the textarea.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor -- long-running-command`
- **AND** the process is running
- **AND** the user has edited the textarea to change `fs:ro:/home/user/data` to `fs:rw:/home/user/data`
- **WHEN** the user clicks the "Restart" button in the web UI
- **THEN** the active process is stopped
- **AND** a new run starts with the edited config (using `fs:rw:/home/user/data`)
- **AND** a fresh access log replaces entries from the previous run

### Use Case: Button states update in real-time

The user sees button labels and disabled states update automatically as the run status changes, without refreshing the page.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor -- long-running-command`
- **AND** the process is running
- **AND** the web UI shows a "Restart" button and an enabled "Stop" button
- **WHEN** the process exits
- **THEN** the "Restart" button label changes to "Start" without page refresh
- **AND** the "Stop" button becomes disabled without page refresh

### Use Case: Access log clears on new run session

When a new run starts, the browser's access log table clears and shows entries from the new run, without a page refresh.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **AND** the user has started `execave --monitor -- ls /home/user/data`
- **AND** the initial run has exited
- **AND** the access log table shows entries from the initial run
- **WHEN** the user starts a new run
- **THEN** the access log table in the browser is cleared without page refresh
- **AND** entries from the new run appear in real-time

## REMOVED Use Cases

### Use Case: View rules alongside the access log
**Reason**: The read-only rules pane is replaced by an editable textarea containing the raw TOML config file. The new "Edit config alongside the access log" use case covers this.
**Migration**: See ADDED "Edit config alongside the access log".

### Use Case: Rules update after restarting execave with a new config
**Reason**: With random port assignment, restarting the execave CLI process binds to a different port, so the browser tab cannot automatically reconnect. Config editing now happens within the same session via the textarea. SSE reconnect within a session is covered by "Config editor syncs on SSE reconnect".
**Migration**: Edit config in the web UI textarea instead of editing the file and restarting execave.

### Use Case: Hover a rule to see matching log entries
**Reason**: The structured rules pane (with individual rule elements) is replaced by a plain textarea. Bidirectional hover highlighting is incompatible with textarea. The matched rule for each log entry remains visible as a tooltip on the log row.
**Migration**: Hover a log entry row to see its matched rule in the tooltip.

### Use Case: Hover a log entry to see its matched rule
**Reason**: The structured rules pane is replaced by a plain textarea. Highlighting a specific rule in the textarea is not feasible. The matched rule for each log entry remains visible as a tooltip on the log row.
**Migration**: The matched rule is shown as a tooltip on each log entry row (no interaction required).
