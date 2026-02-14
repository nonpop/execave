## Why

The `--monitor` flag currently writes access logs to a plain text file. Users must `tail -f` the file in a separate terminal to watch entries during execution. This is workable but primitive — there's no structured view, no filtering, and no connection to the rule that matched each entry. A localhost web UI provides a better monitor experience and is the foundation for the planned interactive monitor-editor loop (run controls, config editing, rule matching).

## What Changes

- **BREAKING**: `--monitor` launches a localhost web UI instead of writing a log file. `--monitor=PORT` is now required (port number, no default). File-based monitor logging is removed.
- New `internal/webui` package: HTTP server serving a single page with a streaming access log table.
- Access log entries stream to the browser via Server-Sent Events (SSE).
- The page displays operation type, target, result, and matched rule for each entry.
- Run status (command, running / exited with code) shown on the page.
- The `accesslog.Logger` gains an in-memory entry buffer so the web server can replay entries on page load and new SSE connections.
- Server lifecycle: starts before the sandbox, survives sandbox exit, stops on Ctrl-C. First Ctrl-C during a run kills the sandbox; Ctrl-C after sandbox exit stops the server.

## Playbooks

### Modified Playbooks

- `monitoring-access`: File-based `--monitor` use cases change to port-based `--monitor=PORT` with web UI. `tail -f` real-time monitoring replaced by browser-based SSE streaming. New use cases for web UI access, server lifecycle, and run status display.

## Capabilities

### New Capabilities

- `web-ui`: Localhost HTTP server that displays streaming access log entries and run status. Covers the web server lifecycle, SSE streaming, entry buffering, page rendering, and CLI integration (`--monitor`).

### Modified Capabilities

- `monitor`: The `--monitor` flag semantics change from file path to port number. File-based logging is removed. The monitor package itself (strace parsing, rule resolution) is unchanged — only the CLI plumbing and output destination change.
- `access-log`: The Logger gains an in-memory entry buffer for web view replay. The write-to-io.Writer behavior is preserved (the web server becomes the writer), but the Logger now also stores entries.

## Impact

- **CLI** (`cmd/execave/main.go`): `--monitor` flag parsing changes (port instead of path), new web server startup/shutdown flow, changed SIGINT handling for two-phase Ctrl-C.
- **New package** (`internal/webui`): HTTP server, SSE handler, HTML template, entry buffer.
- **`internal/accesslog`**: Logger gains entry storage. No changes to filtering, deduplication, or formatting logic.
- **No security boundary changes**: The web server binds to `127.0.0.1` only and is read-only. It does not modify sandbox configuration, rule resolution, or bwrap invocation. The sandboxed process can reach it if the user explicitly allows the port via net rules, but the data is the sandbox's own access log — no new trust boundaries are introduced.
- **Dependencies**: `net/http` from stdlib (no external deps).
