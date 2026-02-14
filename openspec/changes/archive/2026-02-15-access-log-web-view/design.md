## Context

The `--monitor` flag currently writes a formatted text log to a file. The streaming infrastructure is already in place: strace output flows through an `os.Pipe` to the monitor's `processStraceOutput`, which calls `accesslog.Logger.Log()` for each entry. The Logger writes to an `io.Writer` (the log file) under a `sync.Mutex`. Network entries from the proxy also flow through the same Logger concurrently.

This design replaces the file output with a localhost web UI that displays the same entries in real-time via SSE.

## Goals / Non-Goals

**Goals:**
- Streaming access log table in a browser, updated in real-time via SSE
- Run status visible (running / exited with code N)
- Server survives sandbox exit so the user can review logs
- Known/configurable port for discoverability
- Forward-compatible with future restart/config-editing phases

**Non-Goals:**
- Config editing, run controls (restart/stop), rule matching highlights (future phases)
- File-based log output (removed, not preserved alongside)
- Authentication (localhost-only binding is sufficient)
- Persistent storage of log data across server restarts

## Decisions

### 1. Entry buffer in accesslog.Logger

Replace the `io.Writer` with an `entries []Entry` slice. After an entry passes deduplication and filtering, append it to the slice (under the existing mutex) instead of formatting and writing to a writer. Add an `Entries() []Entry` method that returns a snapshot (copy of the slice). The constructor changes from `New(writer io.Writer, managedPaths []string)` to `New(managedPaths []string)`.

The `io.Writer` and text formatting are removed — the Logger's role changes from "format and write" to "filter, deduplicate, and store." Formatting is now the consumer's concern (the web UI template).

**Rationale:** The Logger already has the mutex, the filtering, and the deduplication. With the file output removed, the writer serves no purpose — its only destination would be `io.Discard`. Existing tests that assert on writer output will assert on `Entries()` instead, which is more direct.

**Alternative considered:** Separate entry store that the web server maintains independently. Rejected because it would duplicate deduplication/filtering logic or require the Logger to emit events.

### 2. SSE subscriber notification

The web server needs to push new entries to connected browsers as they arrive. Add a subscriber mechanism to the Logger: a method to register a channel, and notification after each new entry is appended.

`Subscribe() <-chan struct{}` registers a notification channel. When `Log()` appends a new entry, it does a non-blocking send on all subscriber channels. Subscribers call `Entries()` to get the current snapshot (they track their own cursor to avoid re-processing).

`Unsubscribe(<-chan struct{})` removes a subscriber.

**Rationale:** Non-blocking send means a slow subscriber doesn't block logging. The subscriber re-reads the full entry list with its own offset, so it never misses entries even if multiple notifications coalesce.

**Alternative considered:** Sending entries directly through the channel. Rejected because it requires buffered channels sized for worst-case bursts, and a slow consumer could either lose entries (if non-blocking) or block logging (if blocking).

### 3. Run status tracking

The web server needs to display which command is running, whether the sandbox is running, and its exit status. The `webui` package defines `RunStatus` (a DTO with `Running bool`, `ExitCode int`, `Error string`, `Command string`) and a `StatusProvider` interface for read-only access (`Status()`, `Subscribe()`, `Unsubscribe()`). The `Server` receives a `StatusProvider` as a constructor dependency.

The concrete `statusTracker` lives in `cmd/execave` — it owns the mutable state and pub/sub notifications, following the same pattern as `accesslog.Logger`. The CLI orchestrator creates it with the command (`newStatusTracker(command []string)`) and calls `SetRunning()`, `SetExited(code int, err error)`. The command is joined with spaces and included in every `RunStatus` snapshot, so SSE status events always carry the command — enabling cross-session reconnects to display the correct command.

**Rationale:** Status changes originate from the CLI orchestrator, not the web server. The tracker is orchestration logic that belongs with the CLI. The `webui` package only needs read-only access, expressed as the `StatusProvider` interface. This keeps `webui` decoupled from status mutation and avoids a dependency from `webui` on orchestration concerns.

### 4. HTTP server architecture (`internal/webui`)

Single `Server` struct with:
- Reference to `*accesslog.Logger` (for entries and subscriptions)
- `StatusProvider` interface (for status and subscriptions)
- `http.Server` bound to `127.0.0.1:PORT`

Routes:
- `GET /` — Server-rendered HTML page with all current entries baked into the table, plus JS that connects to SSE for live updates. The rendered HTML includes the entry count as a data attribute (e.g., `data-entry-count="50"`) so the JS knows where to resume.
- `GET /events?from=N` — SSE endpoint. Replays entries starting from index N, then streams new entries and status updates as they arrive. Each entry event includes an `id:` field set to the entry index. On reconnect, the browser automatically sends a `Last-Event-ID` header; the server checks this header first, then falls back to the `?from` query param. This eliminates the race between page render and SSE connection, and makes reconnection seamless with no custom JS.

The HTML is a single `html/template` embedded via `embed.FS`. Minimal JS: an `EventSource` that connects to `/events?from=<entry-count>`, appends `<tr>` elements to the table, and updates the status line. Reconnection is handled automatically by `EventSource` + `Last-Event-ID`.

**Rationale:** Server-rendered initial page means the browser gets all existing entries immediately on load (no flash of empty table). The `?from` param handles the initial page-to-SSE handoff, and `Last-Event-ID` handles reconnection — both use the same cursor mechanism server-side. Page refresh also works correctly — the full table is re-rendered and a new SSE connection resumes from the right offset.

### 5. `--monitor` flag semantics change

Change `--monitor` from optional string (file path) to required-value string (port number):
- `--monitor=PORT` → start web UI on specified port
- `--monitor` without a value → error

The flag no longer uses `NoOptDefVal`. A value is always required.

**Rationale:** Avoids bikeshedding on a default port that may conflict with dev servers. The user always knows the port because they always chose it.

### 6. Server lifecycle and SIGINT handling

Startup sequence:
1. Parse config, build resolver (unchanged)
2. Start HTTP server on configured port
3. Print `Monitor: http://127.0.0.1:PORT` to stderr
4. Start proxy if needed (unchanged)
5. Run sandbox with monitoring (unchanged, Logger stores entries in memory)
6. After sandbox exits, update run status, print post-exit message to stderr
7. Block until SIGINT, then exit immediately

SIGINT handling changes from the current single-trap to a state-based approach:
- **While sandbox is running**: All SIGINTs are forwarded to the sandbox child (existing behavior via process group). After the child exits, the pipe drains, and the processing goroutine finishes. Run status is updated. Server stays alive.
- **After sandbox has exited**: The next SIGINT exits immediately without graceful shutdown. The OS closes all HTTP connections when the process exits.

Implementation: SIGINT signals are captured by `signal.Notify` to prevent them from terminating the parent process while the sandbox runs and the pipe drains. After the sandbox exits and the run status is updated, the orchestrator blocks on `<-sigCh` waiting for the next SIGINT, then returns immediately to exit the process.

### 7. HTML/CSS approach

Embedded single-file HTML template with inline CSS. No external dependencies, no build step. The table uses monospace font for path alignment. Entries are color-coded by result: green for OK, red for DENY, yellow for UNKNOWN.

The SSE JS is ~20 lines: connect to `/events`, parse event data (JSON), append rows or update status.

## Risks / Trade-offs

**Entry buffer grows unbounded** → For a single run, the deduplicated entry count is typically tens to hundreds. Even thousands of entries at ~200 bytes each is under 1MB. Acceptable for a session-lived process. If future phases add multi-run support, each run's buffer can be scoped independently.

**SSE reconnection** → If the browser loses the SSE connection (unlikely on localhost), `EventSource` auto-reconnects and sends the `Last-Event-ID` header. The server resumes from that index, so only missing entries are sent. No custom reconnection logic or re-rendering needed.

**Port conflicts** → If port 3030 (or the specified port) is already in use, `net.Listen` fails immediately with a clear error. The user can pick a different port.

**No graceful shutdown on exit** → After the sandbox stops, the user has finished their task and wants to exit immediately when pressing Ctrl-C. The implementation exits directly without calling `httpServer.Shutdown()`, relying on the OS to close open connections. This provides instant response to Ctrl-C instead of waiting for active SSE connections to close.
