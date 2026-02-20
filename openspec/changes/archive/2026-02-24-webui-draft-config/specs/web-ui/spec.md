# Web UI Capability — Delta

## ADDED Requirements

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

The SSE stream SHALL include a `config` event containing a JSON object with `draft` and `saved` fields, both containing the full TOML config text. This event SHALL be sent at the start of each SSE connection (in the initial burst: session, status, config, entries). The `draft` field contains the current server-side draft content; the `saved` field contains the last-saved content. Clients use these to populate the textarea and determine whether the config has been modified.

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

## MODIFIED Requirements

### Requirement: Web server binding

The web UI server SHALL bind to `127.0.0.1` on an OS-assigned random port. Start() SHALL return an error if binding fails. URL() SHALL return the full URL including the access token as a query parameter.

#### Scenario: Server starts and serves HTTP

- **WHEN** Server is started
- **THEN** HTTP requests to the bound address with a valid token are served
- **AND** URL() returns the bound address with the access token (e.g., `http://127.0.0.1:54321?token=abc123...`)

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

## REMOVED Requirements

### Requirement: Rules pane
**Reason**: The read-only rules pane is replaced by an editable textarea containing the raw TOML config file. See ADDED "Config editor textarea".
**Migration**: Use the config editor textarea.

### Requirement: Rules refreshed on SSE reconnect
**Reason**: The `rules` SSE event is replaced by a `config` SSE event that sends both draft and saved content. See ADDED "Config SSE event".
**Migration**: Listen for the `config` SSE event instead of `rules`.

### Requirement: Hover rule highlights matching log entries
**Reason**: The structured rules pane (with individual rule elements) is replaced by a plain textarea. Bidirectional hover highlighting is incompatible with textarea. The matched rule for each log entry remains visible as a tooltip on the log row.
**Migration**: The matched rule is shown in the tooltip on each log entry row.

### Requirement: Hover log entry highlights matched rule
**Reason**: The structured rules pane is replaced by a plain textarea. Highlighting a specific rule in the textarea is not feasible. The matched rule for each log entry remains visible as a tooltip on the log row.
**Migration**: The matched rule is shown in the tooltip on each log entry row.
