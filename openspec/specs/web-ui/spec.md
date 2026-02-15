# Web UI Capability

## Purpose

The web-ui capability provides a localhost web interface for viewing access log entries and sandbox run status in real-time. It replaces file-based log output with a browser-based view.

## Requirements

### Requirement: Web server binding

The web UI server SHALL bind to `127.0.0.1` on the specified port. Start() SHALL return an error if the port is invalid or already in use.

#### Scenario: Server starts and serves HTTP
- **WHEN** Server is started on port 0 (OS-assigned)
- **THEN** HTTP requests to the bound address are served
- **AND** URL() returns the bound address

#### Scenario: Invalid port rejected
- **WHEN** Server is started with port `"notaport"`
- **THEN** Start() returns an error indicating the port is invalid

#### Scenario: Port already in use
- **WHEN** another listener occupies the specified port
- **AND** Server is started on that port
- **THEN** Start() returns an error indicating the port is unavailable

### Requirement: Access log page

GET / SHALL return an HTML page displaying all access log entries in a table with columns: operation type, target, result, and matched rule. The page SHALL include all entries from the Logger at the time of the request.

#### Scenario: Page displays entries
- **WHEN** Logger contains entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **AND** GET / is requested
- **THEN** response contains a table row with operation `READ`, target `/tmp/data/file.txt`, result `OK`, and rule `fs:ro:/tmp/data`

#### Scenario: Page displays all entry types
- **WHEN** Logger contains READ, WRITE, HTTPS, and DENY entries
- **AND** GET / is requested
- **THEN** all entry types are visible in the response

#### Scenario: Page refresh shows current entries
- **WHEN** Logger contains entries
- **AND** GET / is requested twice
- **THEN** both responses contain all entries

### Requirement: Real-time entry streaming

New access log entries SHALL be streamed to connected clients via Server-Sent Events (SSE) at GET /events?from=N. The `from` parameter specifies the entry index to start from. Each SSE event SHALL include an `id` field in the format `<sessionID>:<index>`.

#### Scenario: New entries streamed via SSE
- **WHEN** client is connected to `/events`
- **AND** a new entry is logged
- **THEN** client receives an entry event with the entry data

#### Scenario: SSE replays from cursor
- **WHEN** Logger contains 50 entries
- **AND** client connects to `/events?from=30`
- **THEN** SSE stream starts with entries 30 through 49
- **AND** continues with new entries as they arrive

### Requirement: No entries dropped between page load and SSE

The page render SHALL include the current entry count and session ID. The SSE endpoint SHALL support a `from` query parameter to replay from a specific index. On reconnection with a `Last-Event-ID` header containing the same session ID, the server SHALL resume from the next entry after the last received. Cross-session reconnects (different or malformed session ID) SHALL replay from entry 0.

#### Scenario: Entries during page-to-SSE gap not lost
- **WHEN** GET / returns page with entry count 50
- **AND** entries 50 and 51 arrive before the SSE connection is established
- **AND** client connects to `/events?from=50`
- **THEN** SSE stream includes entries 50 and 51

#### Scenario: SSE reconnection uses Last-Event-ID
- **WHEN** client reconnects with Last-Event-ID `<sessionID>:75` from the same session
- **THEN** server resumes streaming from entry 76

#### Scenario: Cross-session reconnect replays from start
- **WHEN** client connects with Last-Event-ID from a different session or with malformed format
- **THEN** SSE stream replays all entries from entry 0

### Requirement: Run status display

The `StatusProvider` interface and `RunStatus` type move to the `runner` package. The web UI reads status from `*runner.Runner` directly. The display behavior is unchanged — only the source of the data changes. Tests that construct a `MockStatus` implementing `StatusProvider` should use `*runner.Runner` with test helpers instead.

GET / SHALL display the current run status: the sandboxed command, whether the process is running, and (if exited) its exit code. Status updates SHALL be delivered via SSE status events. The command SHALL be included in the RunStatus so that cross-session reconnects display the correct command. The web UI reads status from `*runner.Runner` directly.

#### Scenario: Command shown in page
- **WHEN** the runner has command `echo hello`
- **AND** GET / is requested
- **THEN** response contains `echo hello`

#### Scenario: Cross-session reconnect delivers current command
- **WHEN** client connects to `/events` with Last-Event-ID from a different session
- **THEN** status event in the SSE stream contains the current command

#### Scenario: Running status shown
- **WHEN** the runner reports Running=true
- **AND** GET / is requested
- **THEN** response indicates the process is running

#### Scenario: Exit status shown
- **WHEN** the runner reports Running=false, ExitCode=0
- **AND** GET / is requested
- **THEN** response indicates the process exited with code 0

#### Scenario: Non-zero exit code shown
- **WHEN** the runner reports Running=false, ExitCode=1
- **AND** GET / is requested
- **THEN** response indicates the process exited with code 1

#### Scenario: Status updates streamed via SSE
- **WHEN** client is connected to `/events`
- **AND** the runner status changes
- **THEN** client receives a status event with the updated run status

### Requirement: Run control endpoints

The web UI SHALL expose POST /api/start to start a new monitored run and POST /api/stop to stop the active run. POST /api/start SHALL return 200 on success and 500 with an error message on failure. POST /api/stop SHALL return 200 always.

#### Scenario: Start endpoint triggers a new run
- **WHEN** POST /api/start is called
- **AND** no run is active
- **THEN** response status is 200
- **AND** a new monitored run starts

#### Scenario: Start endpoint restarts an active run
- **WHEN** POST /api/start is called
- **AND** a run is active
- **THEN** response status is 200
- **AND** the previous run is stopped
- **AND** a new run starts with a fresh access log

#### Scenario: Stop endpoint terminates active run
- **WHEN** POST /api/stop is called
- **AND** a run is active
- **THEN** response status is 200
- **AND** the run is terminated

#### Scenario: Stop endpoint when idle
- **WHEN** POST /api/stop is called
- **AND** no run is active
- **THEN** response status is 200

### Requirement: Run control buttons

GET / SHALL display start and stop buttons in the status bar. The start button SHALL show "Start" when no process is running and "Restart" when a process is running. The stop button SHALL always be visible but disabled when no process is running.

#### Scenario: Start button and disabled stop shown when idle
- **WHEN** no run is active
- **AND** GET / is requested
- **THEN** the page displays a "Start" button
- **AND** the page displays a disabled "Stop" button

#### Scenario: Restart button and enabled stop shown when running
- **WHEN** a run is active
- **AND** GET / is requested
- **THEN** the page displays a "Restart" button
- **AND** the page displays an enabled "Stop" button
