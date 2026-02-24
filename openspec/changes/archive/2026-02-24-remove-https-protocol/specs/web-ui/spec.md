## MODIFIED Requirements

### Requirement: Access log page

GET / SHALL return an HTML page displaying all access log entries in a table with columns: operation type, target, result, and matched rule. The page SHALL include all entries from the Logger at the time of the request. Filesystem target paths SHALL be displayed in shortened form (relative to config directory if under it, otherwise `~/...` form if under home directory, otherwise absolute). Rule strings SHALL be shown verbatim as stored in `Entry.Rule`.

#### Scenario: Page displays entries
- **WHEN** Logger contains entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **AND** GET / is requested
- **THEN** response contains a table row with operation `READ`, target `/tmp/data/file.txt`, result `OK`, and rule `fs:ro:/tmp/data`

#### Scenario: Page displays all entry types
- **WHEN** Logger contains READ, WRITE, HTTP, and DENY entries
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
- **WHEN** Logger contains entry (HTTP, `api.example.com:443`, OK, `net:http:api.example.com:443`)
- **AND** GET / is requested
- **THEN** the target column displays `api.example.com:443` unchanged
