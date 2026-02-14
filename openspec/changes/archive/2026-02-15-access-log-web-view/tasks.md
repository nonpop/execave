## 1. Refactor accesslog.Logger

- [x] 1.1 Remove `io.Writer` field and `writeLogEntry` method from Logger. Change constructor from `New(writer, managedPaths)` to `New(managedPaths)`. Add `entries []Entry` slice. `Log()` appends to slice instead of writing. Add `Entries() []Entry` that returns a copy.
- [x] 1.2 Add `Subscribe()`/`Unsubscribe()` for entry change notification. Non-blocking send on subscriber channels when new entry is appended.
- [x] 1.3 Update accesslog tests to assert on `Entries()` instead of writer output.
- [x] 1.4 Update all callers of `accesslog.New()` — `cmd/execave/main.go` and `internal/proxy/proxy.go` (and any test helpers).

## 2. Change `--monitor` flag semantics

- [x] 2.1 Change `--monitor` from optional-value string (file path) to required-value string (port number). Remove `NoOptDefVal`. Validate port number. Error on missing value.
- [x] 2.2 Remove `createAccessLogWriter` and file-based log setup from `cmd/execave/main.go`.
- [x] 2.3 Update existing monitor E2E tests to use port-based `--monitor=PORT` instead of file path.

## 3. Web UI server (`internal/webui`)

- [x] 3.1 Create `internal/webui` package with `Server` struct. Constructor takes `*accesslog.Logger`, `StatusProvider`, and port. `Start()` binds to `127.0.0.1:PORT`, `Shutdown()` for graceful stop.
- [x] 3.2 Define `RunStatus` DTO and `StatusProvider` interface in `webui`. Add concrete `statusTracker` in `cmd/execave`: `SetRunning()`, `SetExited(code, err)`, `Status()`, `Subscribe()`/`Unsubscribe()`. Follows same pub/sub pattern as `accesslog.Logger`.
- [x] 3.3 Implement `GET /` handler: server-rendered HTML template with entry table and `data-entry-count` attribute. Embedded via `embed.FS`.
- [x] 3.4 Implement `GET /events?from=N` SSE handler: replay entries from index N, stream new entries and status updates. Include `id:` field per event. Support `Last-Event-ID` header (check before `?from` param).
- [x] 3.5 Create HTML template with inline CSS and JS. Table with OP/TARGET/RESULT/RULE columns. Color-coded results. `EventSource` JS that appends rows and updates status line.

## 4. CLI integration and lifecycle

- [x] 4.1 Wire web UI server into monitor mode in `cmd/execave/main.go`: start server before sandbox, print URL to stderr, set run status on sandbox exit, print post-exit message to stderr.
- [x] 4.2 Implement state-based SIGINT handling: while sandbox alive, SIGINTs pass through to child. After sandbox exits, next SIGINT exits immediately without graceful shutdown.

## 5. E2E tests

- [x] 5.1 E2E test: `--monitor=PORT` starts server on correct port, page is accessible.
- [x] 5.2 E2E test: invalid port and missing port value produce errors.
- [x] 5.3 E2E test: page displays access log entries with correct columns after sandbox runs.
- [x] 5.4 E2E test: SSE streams new entries in real-time during sandbox execution.
- [x] 5.5 E2E test: server remains accessible after sandbox exits; SIGINT after exit stops server.
- [x] 5.6 E2E test: entries during page-to-SSE gap are not dropped (cursor-based handoff).

## 6. Command display

- [x] 6.1 Add `Command string` to `RunStatus`. Update `statusTracker` to accept `command []string` in constructor, join with space, include in `SetRunning()`/`SetExited()`. Pass command from `runMonitored()`.
- [x] 6.2 Display command in HTML header. Update JS status event listener to set command text on reconnect.
- [x] 6.3 Update `mockStatus` in tests. Add tests for command in HTML response and SSE status event JSON.
- [x] 6.4 E2E test: command shown in HTML page header.
- [x] 6.5 E2E test: command present in SSE status event JSON (enables cross-session command update).

## 7. Docs

- [x] 7.1 Update `docs/architecture.md` for new `internal/webui` package.
- [x] 7.2 Update `README.md` monitor section for `--monitor=PORT` web UI workflow.
- [x] 7.3 Update `openspec/config.yaml` context section.
