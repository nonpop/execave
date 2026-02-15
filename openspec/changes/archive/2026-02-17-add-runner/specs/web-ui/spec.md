## ADDED Requirements

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

## MODIFIED Requirements

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
