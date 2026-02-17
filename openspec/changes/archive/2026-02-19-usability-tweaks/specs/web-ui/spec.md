## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Access log page

GET / SHALL return an HTML page displaying all access log entries in a table with columns: operation type, target, result, and matched rule. The page SHALL include all entries from the Logger at the time of the request. Filesystem target paths SHALL be displayed in shortened form (relative to config directory if under it, otherwise `~/...` form if under home directory, otherwise absolute). Rule strings SHALL be shown verbatim as stored in `Entry.Rule`.

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
- **WHEN** Logger contains entry (HTTPS, `api.example.com:443`, OK, `net:https:api.example.com:443`)
- **AND** GET / is requested
- **THEN** the target column displays `api.example.com:443` unchanged
