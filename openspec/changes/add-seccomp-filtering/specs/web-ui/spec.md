## ADDED Requirements

### Requirement: Allow all syscalls checkbox

GET / SHALL display an "Allow all syscalls" checkbox in the controls area. The checkbox SHALL be unchecked by default (seccomp filtering ON). The initial checked state SHALL be determined by the server's `allowAllSyscalls` field (set from CLI flag).

#### Scenario: Checkbox unchecked by default
- **WHEN** the server is created with `allowAllSyscalls=false`
- **AND** GET / is requested
- **THEN** the "Allow all syscalls" checkbox is unchecked

#### Scenario: Checkbox checked when CLI flag set
- **WHEN** the server is created with `allowAllSyscalls=true`
- **AND** GET / is requested
- **THEN** the "Allow all syscalls" checkbox is checked

### Requirement: Start sends allow-all-syscalls state

POST /api/start SHALL read an `allow-all-syscalls` query parameter. When present and equal to `"1"`, the server SHALL call `runner.SetAllowAllSyscalls(true)` before starting the run. Otherwise, the server SHALL call `runner.SetAllowAllSyscalls(false)`.

#### Scenario: Start with checkbox checked
- **WHEN** POST /api/start is called with `?allow-all-syscalls=1`
- **THEN** the runner's `allowAllSyscalls` is set to true before the run starts

#### Scenario: Start with checkbox unchecked
- **WHEN** POST /api/start is called without `allow-all-syscalls` query param
- **THEN** the runner's `allowAllSyscalls` is set to false before the run starts

### Requirement: SSE status includes allow-all-syscalls state

SSE status events SHALL include an `allowAllSyscalls` boolean field reflecting the current runner state. This enables the frontend to sync the checkbox on reconnection.

#### Scenario: Status event includes allowAllSyscalls
- **WHEN** a client connects to `/events`
- **THEN** the SSE status event includes `"allowAllSyscalls": false` (or true if set)
