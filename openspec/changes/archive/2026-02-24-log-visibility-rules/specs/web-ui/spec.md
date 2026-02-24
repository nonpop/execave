## ADDED Requirements

### Requirement: Denied-only filter

The web UI SHALL display only DENY and UNKNOWN entries by default. A "Denied only" checkbox (default: checked) SHALL control this filter. When unchecked, OK entries are also displayed. The filter SHALL apply to both the initial page render and dynamically streamed SSE entries.

#### Scenario: Default view hides OK entries

- **WHEN** Logger contains entries with results OK, DENY, and UNKNOWN
- **AND** GET / is requested
- **THEN** only DENY and UNKNOWN entries are visible in the rendered page

#### Scenario: Unchecking denied-only reveals OK entries

- **WHEN** the client unchecks the "Denied only" checkbox
- **THEN** OK entries become visible without page reload

#### Scenario: Re-checking denied-only hides OK entries

- **WHEN** the client re-checks the "Denied only" checkbox
- **THEN** OK entries are hidden again without page reload

### Requirement: Nolog filter

The web UI SHALL apply log rule resolution to determine entry visibility. A "Apply nolog rules" checkbox (default: checked) SHALL control this filter. When checked, entries whose target matches a `nolog` rule (and is not overridden by a more specific `log` rule) are hidden. When unchecked, all entries are shown regardless of log rules. The filter SHALL apply to both the initial page render and dynamically streamed SSE entries.

#### Scenario: Nolog rule hides matching entries

- **WHEN** config contains `fs:nolog:/home/user/project`
- **AND** Logger contains a DENY entry for `/home/user/project/cache/data`
- **AND** GET / is requested with "Apply nolog rules" checked
- **THEN** the entry is not visible

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

## MODIFIED Requirements

### Requirement: Access log page

GET / SHALL return an HTML page displaying access log entries in a table with columns: operation type, target, result, and matched rule. The page SHALL include all entries from the Logger at the time of the request. Filesystem target paths SHALL be displayed in shortened form (relative to config directory if under it, otherwise `~/...` form if under home directory, otherwise absolute). Rule strings SHALL be shown verbatim as stored in `Entry.Rule`. By default, only DENY and UNKNOWN entries are visible; OK entries are hidden by the "Denied only" filter. Entries matching nolog rules are hidden by the "Apply nolog rules" filter. The page SHALL include checkboxes to toggle both filters.

#### Scenario: Page displays entries

- **WHEN** Logger contains entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **AND** GET / is requested
- **THEN** response contains a table row with operation `READ`, target `/tmp/data/file.txt`, result `OK`, and rule `fs:ro:/tmp/data`

#### Scenario: Page displays all entry types

- **WHEN** Logger contains READ, WRITE, HTTPS, and DENY entries
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

- **WHEN** Logger contains entry (HTTPS, `api.example.com:443`, OK, `net:https:api.example.com:443`)
- **AND** GET / is requested
- **THEN** the target column displays `api.example.com:443` unchanged

#### Scenario: Filter checkboxes displayed

- **WHEN** GET / is requested
- **THEN** the page contains a "Denied only" checkbox (checked by default) and an "Apply nolog rules" checkbox (checked by default)
