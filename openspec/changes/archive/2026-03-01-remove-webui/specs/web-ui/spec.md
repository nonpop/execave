## REMOVED Requirements

### Requirement: Web server binding
**Reason**: Web UI removed entirely. No HTTP server needed.
**Migration**: Use `--monitor` for stderr or `--monitor=<path>` for file-based text log.

### Requirement: Access log page
**Reason**: Web UI removed. Access log is displayed via text log output.
**Migration**: Text log output includes the same columns (result, operation, target, rule).

### Requirement: Denied-only filter
**Reason**: Web UI removed. Denied-only filtering is controlled by `--show-allowed` flag in text log mode.
**Migration**: Use `--show-allowed` to include OK entries.

### Requirement: Nolog filter
**Reason**: Web UI removed. Nolog filtering is controlled by `--show-nolog` flag in text log mode.
**Migration**: Use `--show-nolog` to include nolog entries.

### Requirement: Filter checkboxes displayed
**Reason**: Web UI removed. No checkboxes.
**Migration**: Use CLI flags `--show-allowed` and `--show-nolog`.

### Requirement: Independent filter axes
**Reason**: Web UI removed. Filter independence is preserved in text log mode.
**Migration**: Both `--show-allowed` and `--show-nolog` operate independently in text log.

### Requirement: SSE entry events include nolog metadata
**Reason**: Web UI removed. No SSE streaming.
**Migration**: Text log applies nolog filtering server-side.

### Requirement: Path shortening for display
**Reason**: Web UI removed. Path shortening is handled by `logfilter.ShortenPath`, used by text log.
**Migration**: Text log uses the same path shortening logic.

### Requirement: SSE entry events include shortened target paths
**Reason**: Web UI removed. No SSE events.
**Migration**: Text log outputs shortened paths directly.

### Requirement: Real-time entry streaming
**Reason**: Web UI removed. No SSE streaming.
**Migration**: Use `--monitor=<path>` with `tail -f` for real-time viewing.

### Requirement: No entries dropped between page load and SSE
**Reason**: Web UI removed. No page/SSE gap to bridge.
**Migration**: Text log is a single output stream with no gaps.

### Requirement: Run status display
**Reason**: Web UI removed. No status display in text log mode.
**Migration**: Observe process state directly in the terminal.

### Requirement: Run control endpoints
**Reason**: Web UI removed. No HTTP endpoints for start/stop/save/revert.
**Migration**: Use CLI: re-run for start, Ctrl-C for stop, edit file for config changes.

### Requirement: Run control buttons
**Reason**: Web UI removed. No browser buttons.
**Migration**: Use CLI commands.

### Requirement: Config editor textarea
**Reason**: Web UI removed. No textarea.
**Migration**: Edit config file in any text editor.

### Requirement: Config SSE event
**Reason**: Web UI removed. No SSE events.
**Migration**: No action needed.

### Requirement: Save endpoint
**Reason**: Web UI removed. No save endpoint.
**Migration**: Save config file from text editor.

### Requirement: Revert endpoint
**Reason**: Web UI removed. No revert endpoint.
**Migration**: Use editor undo or version control.

### Requirement: Access token authentication
**Reason**: Web UI removed. No HTTP server to authenticate.
**Migration**: No action needed.
