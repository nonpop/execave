# Web UI Capability

## Purpose

The web-ui capability provides a localhost web interface for viewing access log entries and sandbox run status in real-time. It replaces file-based log output with a browser-based view.

## Requirements

### Requirement: Web server binding

The web UI server SHALL bind to `127.0.0.1` on an OS-assigned random port. Start() SHALL return an error if binding fails. URL() SHALL return the full URL including the access token as a query parameter.

#### Scenario: Server starts and serves HTTP

- **WHEN** Server is started
- **THEN** HTTP requests to the bound address with a valid token are served
- **AND** URL() returns the bound address with the access token (e.g., `http://127.0.0.1:54321?token=abc123...`)

### Requirement: Access log page

GET / SHALL return an HTML page displaying access log entries in a table with columns: operation type, target, result, and matched rule. The page SHALL include all entries from the Logger at the time of the request. Filesystem target paths SHALL be displayed in shortened form (relative to config directory if under it, otherwise `~/...` form if under home directory, otherwise absolute). Rule strings SHALL be shown verbatim as stored in `Entry.Rule`. By default, only DENY and UNKNOWN entries are visible; OK entries are hidden by the "Denied only" filter. Entries matching nolog rules are hidden by the "Apply nolog rules" filter. The page SHALL include checkboxes to toggle both filters.

#### Scenario: Page displays entries

- **WHEN** Logger contains entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **AND** GET / is requested
- **THEN** response contains a table row with operation `READ`, target `/tmp/data/file.txt`, result `OK`, and rule `fs:ro:/tmp/data`

#### Scenario: Page displays all entry types

- **WHEN** Logger contains READ, WRITE, HTTP, and DENY entries
- **AND** GET / is requested
- **THEN** all entry types are present in the response (some may be hidden by default filters)

#### Scenario: Page refresh shows current entries

- **WHEN** Logger contains entries
- **AND** GET / is requested twice
- **THEN** both responses contain all entries

#### Scenario: Filesystem target path shortened to relative form

- **WHEN** config is at `/home/user/project/execave.toml`
- **AND** Logger contains entry (READ, `/home/user/project/src/main.go`, OK, `fs:rw:~/project`)
- **AND** GET / is requested
- **THEN** the target column displays `src/main.go`
- **AND** the rule column displays `fs:rw:~/project`

#### Scenario: Filesystem target path shortened to tilde form

- **WHEN** config is at `/home/user/project/execave.toml`
- **AND** Logger contains entry (READ, `/home/user/.ssh/id_rsa`, DENY, `no-matching-rule`)
- **AND** GET / is requested
- **THEN** the target column displays `~/.ssh/id_rsa`

#### Scenario: Non-filesystem target paths not shortened

- **WHEN** Logger contains entry (HTTP, `api.example.com:443`, OK, `net:http:api.example.com:443`)
- **AND** GET / is requested
- **THEN** the target column displays `api.example.com:443` unchanged

#### Scenario: Filter checkboxes displayed

- **WHEN** GET / is requested
- **THEN** the page contains a "Denied only" checkbox (checked by default) and an "Apply nolog rules" checkbox (checked by default)

### Requirement: Denied-only filter

The web UI SHALL display only DENY and UNKNOWN entries by default. A "Denied only" checkbox SHALL control this filter. The initial checked state SHALL be determined by server-side configuration: checked when `FilterDefaults.ShowAllowed` is false (default), unchecked when true. When unchecked, OK entries are also displayed. The filter SHALL apply to both the initial page render and dynamically streamed SSE entries.

#### Scenario: Default view hides OK entries

- **WHEN** Logger contains entries with results OK, DENY, and UNKNOWN
- **AND** FilterDefaults.ShowAllowed is false
- **AND** GET / is requested
- **THEN** only DENY and UNKNOWN entries are visible in the rendered page
- **AND** the "Denied only" checkbox is checked

#### Scenario: ShowAllowed unchecks denied-only checkbox

- **WHEN** FilterDefaults.ShowAllowed is true
- **AND** GET / is requested
- **THEN** OK entries are visible in the rendered page
- **AND** the "Denied only" checkbox is unchecked

#### Scenario: Unchecking denied-only reveals OK entries

- **WHEN** the client unchecks the "Denied only" checkbox
- **THEN** OK entries become visible without page reload

#### Scenario: Re-checking denied-only hides OK entries

- **WHEN** the client re-checks the "Denied only" checkbox
- **THEN** OK entries are hidden again without page reload

### Requirement: Nolog filter

The web UI SHALL apply log rule resolution to determine entry visibility. A "Apply nolog rules" checkbox SHALL control this filter. The initial checked state SHALL be determined by server-side configuration: checked when `FilterDefaults.ShowNolog` is false (default), unchecked when true. When checked, entries whose target matches a `nolog` rule (and is not overridden by a more specific `log` rule) are hidden. When unchecked, all entries are shown regardless of log rules. The filter SHALL apply to both the initial page render and dynamically streamed SSE entries.

#### Scenario: Nolog rule hides matching entries

- **WHEN** config contains `fs:nolog:/home/user/project`
- **AND** FilterDefaults.ShowNolog is false
- **AND** Logger contains a DENY entry for `/home/user/project/cache/data`
- **AND** GET / is requested with "Apply nolog rules" checked
- **THEN** the entry is not visible
- **AND** the "Apply nolog rules" checkbox is checked

#### Scenario: ShowNolog unchecks apply-nolog checkbox

- **WHEN** FilterDefaults.ShowNolog is true
- **AND** GET / is requested
- **THEN** nolog-suppressed entries are visible in the rendered page
- **AND** the "Apply nolog rules" checkbox is unchecked

#### Scenario: Unchecking nolog filter reveals suppressed entries

- **WHEN** config contains `fs:nolog:/home/user/project`
- **AND** Logger contains entries for paths under `/home/user/project`
- **AND** the client unchecks the "Apply nolog rules" checkbox
- **THEN** suppressed entries become visible without page reload

#### Scenario: Log rule override makes entry visible despite nolog

- **WHEN** config contains `fs:nolog:/home/user/project` and `fs:log:/home/user/project/secret`
- **AND** Logger contains a DENY entry for `/home/user/project/secret/key.pem`
- **AND** GET / is requested with "Apply nolog rules" checked
- **THEN** the entry is visible (log rule overrides nolog)

### Requirement: Filter checkboxes displayed

GET / SHALL include a "Denied only" checkbox and an "Apply nolog rules" checkbox. The initial checked state of each checkbox SHALL be determined by the server's `FilterDefaults` configuration, not hardcoded.

#### Scenario: Default filter state (no flags)

- **WHEN** FilterDefaults has ShowAllowed=false and ShowNolog=false
- **AND** GET / is requested
- **THEN** the "Denied only" checkbox is checked
- **AND** the "Apply nolog rules" checkbox is checked

#### Scenario: Both filters overridden

- **WHEN** FilterDefaults has ShowAllowed=true and ShowNolog=true
- **AND** GET / is requested
- **THEN** the "Denied only" checkbox is unchecked
- **AND** the "Apply nolog rules" checkbox is unchecked

### Requirement: Independent filter axes

The denied-only filter and nolog filter SHALL operate independently. An entry must pass both filters to be displayed. Neither filter overrides the other.

#### Scenario: OK entry hidden even when nolog says visible

- **WHEN** "Denied only" is checked and "Apply nolog rules" is checked
- **AND** Logger contains an OK entry for a path not matching any nolog rule
- **THEN** the entry is hidden (blocked by mode filter, even though nolog filter passes)

#### Scenario: Nolog entry hidden even when mode says visible

- **WHEN** "Denied only" is unchecked (show all) and "Apply nolog rules" is checked
- **AND** Logger contains an OK entry matching a nolog rule
- **THEN** the entry is hidden (blocked by nolog filter, even though mode filter passes)

#### Scenario: Entry visible only when both filters pass

- **WHEN** "Denied only" is unchecked and "Apply nolog rules" is unchecked
- **AND** Logger contains entries of all result types including nolog matches
- **THEN** all entries are visible

### Requirement: SSE entry events include nolog metadata

SSE entry events SHALL include a `nolog` boolean field indicating whether the entry matches a nolog rule (as resolved by the log rule resolvers). The client uses this field to apply or skip nolog filtering without re-resolving rules.

#### Scenario: SSE entry event with nolog=true

- **WHEN** config contains `fs:nolog:/home/user/project`
- **AND** a new entry for `/home/user/project/cache/data` is logged
- **AND** a client is connected to GET /events
- **THEN** the SSE entry event contains `"nolog":true`

#### Scenario: SSE entry event with nolog=false

- **WHEN** no log rule matches the entry's target
- **AND** a new entry is logged
- **AND** a client is connected to GET /events
- **THEN** the SSE entry event contains `"nolog":false`

### Requirement: Path shortening for display

The web UI SHALL shorten absolute filesystem target paths for display using the first applicable form in priority order: the path relative to configDir (if the path is under configDir), the `~/...` form (if the path is under homeDir), or the absolute path otherwise. Non-filesystem targets (network entries) SHALL NOT be shortened.

#### Scenario: Path under configDir shortened to relative
- **WHEN** configDir is `"/home/user/project"` and homeDir is `"/home/user"`
- **AND** target path is `"/home/user/project/src/main.go"`
- **THEN** the shortened form is `"src/main.go"`

#### Scenario: Path under homeDir but outside configDir shortened to tilde form
- **WHEN** configDir is `"/home/user/project"` and homeDir is `"/home/user"`
- **AND** target path is `"/home/user/.ssh/id_rsa"`
- **THEN** the shortened form is `"~/.ssh/id_rsa"`

#### Scenario: Path under both homeDir and configDir uses configDir-relative form
- **WHEN** configDir is `"/home/user/project"` and homeDir is `"/home/user"`
- **AND** target path is `"/home/user/project/src/main.go"`
- **THEN** the shortened form is `"src/main.go"` (configDir-relative takes priority over `~/project/src/main.go`)

#### Scenario: Path outside homeDir shown as absolute
- **WHEN** configDir is `"/home/user/project"` and homeDir is `"/home/user"`
- **AND** target path is `"/usr/lib/libc.so"`
- **THEN** the shortened form is `"/usr/lib/libc.so"`

#### Scenario: Path equal to configDir shortened to dot
- **WHEN** configDir is `"/home/user/project"` and homeDir is `"/home/user"`
- **AND** target path is `"/home/user/project"`
- **THEN** the shortened form is `"."`

#### Scenario: Empty homeDir disables tilde shortening
- **WHEN** homeDir is `""`
- **THEN** tilde form is never used; only relative or absolute forms are candidates

### Requirement: SSE entry events include shortened target paths

SSE entry events dispatched via GET /events SHALL include the target path in shortened form, consistent with the HTML page rendering.

#### Scenario: SSE entry event uses shortened path
- **WHEN** config is at `/home/user/project/execave.toml`
- **AND** a new entry (READ, `/home/user/project/src/main.go`, OK, `fs:rw:~/project`) is logged
- **AND** a client is connected to GET /events
- **THEN** the SSE entry event contains `"target":"src/main.go"`

### Requirement: Real-time entry streaming

New access log entries SHALL be streamed to connected clients via Server-Sent Events (SSE) at GET /events?from=N. The `from` parameter specifies the entry index to start from. Each SSE event SHALL include an `id` field containing the numeric entry index.

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

The page render SHALL include the current entry count. The SSE endpoint SHALL support a `from` query parameter to replay from a specific index. On reconnection with a numeric `Last-Event-ID` header, the server SHALL resume from the next entry after the last received index. Stale reconnects (where the Last-Event-ID exceeds the current entry count) SHALL send a `clear` event and replay all entries from 0. Malformed (non-numeric) Last-Event-ID values SHALL replay from entry 0.

#### Scenario: Entries during page-to-SSE gap not lost
- **WHEN** GET / returns page with entry count 50
- **AND** entries 50 and 51 arrive before the SSE connection is established
- **AND** client connects to `/events?from=50`
- **THEN** SSE stream includes entries 50 and 51

#### Scenario: SSE reconnection uses Last-Event-ID
- **WHEN** client reconnects with Last-Event-ID `75`
- **THEN** server resumes streaming from entry 76

#### Scenario: Stale reconnect replays from start
- **WHEN** client connects with Last-Event-ID exceeding the current entry count
- **THEN** server sends a `clear` event
- **AND** SSE stream replays all entries from entry 0

#### Scenario: Malformed Last-Event-ID replays from start
- **WHEN** client connects with a non-numeric Last-Event-ID
- **THEN** SSE stream replays all entries from entry 0

### Requirement: Run status display

The `StatusProvider` interface and `RunStatus` type move to the `runner` package. The web UI reads status from `*runner.Runner` directly. The display behavior is unchanged — only the source of the data changes. Tests that construct a `MockStatus` implementing `StatusProvider` should use `*runner.Runner` with test helpers instead.

GET / SHALL display the current run status: the sandboxed command, whether the process is running, and (if exited) its exit code. Status updates SHALL be delivered via SSE status events. The command SHALL be included in the RunStatus so that stale reconnects display the correct command. The web UI reads status from `*runner.Runner` directly.

#### Scenario: Command shown in page
- **WHEN** the runner has command `echo hello`
- **AND** GET / is requested
- **THEN** response contains `echo hello`

#### Scenario: Stale reconnect delivers current command
- **WHEN** client connects to `/events` with a stale Last-Event-ID exceeding the current entry count
- **THEN** server sends a `clear` event followed by a status event containing the current command

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

The web UI SHALL expose POST /api/start to start a new monitored run, POST /api/stop to stop the active run, POST /api/save to save config to disk, and POST /api/revert to reset the draft config. POST /api/start SHALL accept raw TOML config text as the request body. The server SHALL parse and validate the config via `config.ParseTOML`. If valid, the server SHALL call `OnConfigChange` with the parsed config, then start the run. If the TOML is invalid, the server SHALL respond with 400 and an error message without starting a run. The draft content SHALL be updated to the submitted body regardless of validation success. POST /api/stop SHALL return 200 always.

#### Scenario: Start endpoint triggers a new run with config

- **WHEN** POST /api/start is called with valid TOML config in the body
- **AND** no run is active
- **THEN** response status is 200
- **AND** a new monitored run starts using the submitted config

#### Scenario: Start endpoint restarts an active run

- **WHEN** POST /api/start is called with valid TOML config in the body
- **AND** a run is active
- **THEN** response status is 200
- **AND** the previous run is stopped
- **AND** a new run starts with a fresh access log using the submitted config

#### Scenario: Restart sends clear event to SSE clients

- **WHEN** POST /api/start is called with valid TOML config
- **AND** an SSE client is connected
- **THEN** the SSE client receives a `clear` event signaling that previous log entries should be discarded

#### Scenario: Start with invalid config rejected

- **WHEN** POST /api/start is called with TOML containing `rules = ["badprefix:something"]`
- **THEN** response status is 400
- **AND** the response body contains an error message
- **AND** no run is started
- **AND** the server's draft content is updated to the submitted body

#### Scenario: Start calls OnConfigChange before starting run

- **WHEN** POST /api/start is called with valid TOML config
- **AND** OnConfigChange is set
- **THEN** OnConfigChange is called with the parsed config before the run starts

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

### Requirement: Config editor textarea

GET / SHALL display an editable textarea containing the raw TOML config file (verbatim, including comments) in the left pane where the rules pane previously appeared. The textarea content SHALL be initialized from the server's current draft content.

#### Scenario: Config textarea displayed on page load

- **WHEN** the server is constructed with config content `rules = ["fs:ro:/usr/lib"]`
- **AND** GET / is requested
- **THEN** the response contains a textarea with the text `rules = ["fs:ro:/usr/lib"]`

#### Scenario: Config textarea preserves comments

- **WHEN** the server is constructed with config content containing TOML comments
- **AND** GET / is requested
- **THEN** the textarea contains the comments verbatim

### Requirement: Config SSE event

The SSE stream SHALL include a `config` event containing a JSON object with `draft` and `saved` fields, both containing the full TOML config text. This event SHALL be sent at the start of each SSE connection (in the initial burst: status, config, entries). The `draft` field contains the current server-side draft content; the `saved` field contains the last-saved content. Clients use these to populate the textarea and determine whether the config has been modified.

#### Scenario: Config event sent on SSE connect

- **WHEN** a client connects to `/events`
- **THEN** the SSE stream includes a `config` event with JSON `{"draft": "...", "saved": "..."}`

#### Scenario: Config event reflects draft and saved state

- **WHEN** the server's draft content differs from the saved content (e.g., after a Start with edited config)
- **AND** a client connects to `/events`
- **THEN** the `config` event's `draft` field contains the current draft content
- **AND** the `config` event's `saved` field contains the last-saved content
- **AND** `draft` and `saved` are different

#### Scenario: Config event after save shows matching draft and saved

- **WHEN** the server's draft has been saved (via POST /api/save)
- **AND** a client connects to `/events`
- **THEN** the `config` event's `draft` and `saved` fields are equal

### Requirement: Save endpoint

POST /api/save SHALL accept raw TOML config text as the request body. It SHALL parse and validate the content via `config.ParseTOML`. If valid, it SHALL write the content to the config file path and update both the server's saved and draft content, then respond with 200. If the TOML is invalid or contains invalid rules, it SHALL respond with 400 and an error message without writing to disk.

#### Scenario: Save valid config writes to file

- **WHEN** POST /api/save is called with valid TOML content `rules = ["fs:ro:/usr/lib"]`
- **THEN** response status is 200
- **AND** the config file on disk contains the submitted content
- **AND** the server's saved and draft content are both updated

#### Scenario: Save invalid config rejected

- **WHEN** POST /api/save is called with content `rules = ["badprefix:something"]`
- **THEN** response status is 400
- **AND** the response body contains an error message
- **AND** the config file on disk is unchanged

#### Scenario: Save malformed TOML rejected

- **WHEN** POST /api/save is called with content that is not valid TOML
- **THEN** response status is 400
- **AND** the config file on disk is unchanged

### Requirement: Revert endpoint

POST /api/revert SHALL reset the server's draft content to the last-saved content. It SHALL respond with 200 and the saved content as `text/plain` in the response body.

#### Scenario: Revert resets draft to saved

- **WHEN** the server's draft content differs from the saved content
- **AND** POST /api/revert is called
- **THEN** response status is 200
- **AND** the response body contains the saved config content
- **AND** the server's draft content equals the saved content

#### Scenario: Revert when not modified

- **WHEN** the server's draft content equals the saved content
- **AND** POST /api/revert is called
- **THEN** response status is 200
- **AND** the response body contains the saved config content

### Requirement: Access token authentication

The server SHALL generate a random access token at construction time. Every HTTP request (GET, POST, SSE) SHALL require a valid `?token=` query parameter matching the generated token. Requests without the token or with an incorrect token SHALL receive 403 Forbidden.

#### Scenario: Request with valid token succeeds

- **WHEN** GET / is requested with the correct `?token=` parameter
- **THEN** the server responds normally (200)

#### Scenario: Request without token rejected

- **WHEN** GET / is requested without a `?token=` parameter
- **THEN** the server responds with 403

#### Scenario: Request with wrong token rejected

- **WHEN** GET / is requested with an incorrect `?token=` parameter
- **THEN** the server responds with 403

#### Scenario: Token required on all endpoints

- **WHEN** requests are made to `/`, `/events`, `/api/start`, `/api/stop`, `/api/save`, and `/api/revert` without a `?token=` parameter
- **THEN** all respond with 403

#### Scenario: SSE connection requires token

- **WHEN** a client connects to `/events` with the correct `?token=` parameter
- **THEN** SSE events are streamed normally
- **AND** a client connecting without the token receives 403
