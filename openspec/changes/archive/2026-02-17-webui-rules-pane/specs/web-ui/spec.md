## MODIFIED Requirements

### Requirement: Access log page

GET / SHALL return an HTML page displaying all access log entries in a table with columns: operation type, target, and result. The matched rule SHALL be available as a tooltip on each row. The page SHALL include all entries from the Logger at the time of the request.

#### Scenario: Page displays entries
- **WHEN** Logger contains entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **AND** GET / is requested
- **THEN** response contains a table row with operation `READ`, target `/tmp/data/file.txt`, and result `OK`
- **AND** the row has the matched rule `fs:ro:/tmp/data` as a tooltip

## ADDED Requirements

### Requirement: Rules pane

GET / SHALL display all config rules in a rules pane to the left of the access log table. Rules SHALL be listed in config order (filesystem rules followed by network rules). Each rule SHALL display its raw rule string (e.g. `fs:ro:/usr/lib`). The rules pane SHALL be read-only.

#### Scenario: Rules displayed on page load

- **WHEN** the server is constructed with a config containing rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** GET / is requested
- **THEN** the response contains a rules pane with `fs:ro:/usr/lib` and `fs:rw:/tmp` in that order

#### Scenario: Empty rules displayed

- **WHEN** the server is constructed with a config containing no rules
- **AND** GET / is requested
- **THEN** the rules pane is present but contains no rule entries

#### Scenario: Both fs and net rules displayed

- **WHEN** the server is constructed with a config containing `fs:ro:/usr/lib` and `net:allow:example.com:443`
- **AND** GET / is requested
- **THEN** the response contains both rules in the rules pane

### Requirement: Rules refreshed on SSE reconnect

The SSE stream SHALL include a `rules` event containing the current config rules as a JSON array of raw rule strings. This event SHALL be sent at the start of each SSE connection (alongside the `session` and `status` events). When the client receives a `rules` event, it SHALL replace the rules pane content with the received rules.

#### Scenario: Rules event sent on SSE connect

- **WHEN** a client connects to `/events`
- **THEN** the SSE stream includes a `rules` event with the current config rules as a JSON array

#### Scenario: Rules pane updated on cross-session reconnect

- **WHEN** the server is constructed with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** a client is connected to `/events`
- **AND** the SSE connection drops and reconnects to a server with rules `fs:ro:/opt` and `net:allow:example.com:443`
- **THEN** the rules pane displays `fs:ro:/opt` and `net:allow:example.com:443`
- **AND** the previously displayed rules are no longer shown

#### Scenario: Hover listeners work after rules refresh

- **WHEN** the rules pane has been updated via a `rules` SSE event
- **AND** the user hovers over a rule in the refreshed pane
- **THEN** matching log entries are highlighted

### Requirement: Hover rule highlights matching log entries

When a rule in the rules pane is hovered, the access log entries whose matched rule equals that rule string SHALL be visually highlighted. Log entries matched by other rules or with no matched rule SHALL NOT be highlighted. The highlighting SHALL apply to entries already in the DOM and entries added via SSE while the hover is active.

#### Scenario: Hovering a rule highlights its entries

- **WHEN** the rules pane contains rule `fs:ro:/usr/lib`
- **AND** the access log contains entries with matched rule `fs:ro:/usr/lib` and entries with matched rule `fs:rw:/tmp`
- **AND** the user hovers over the rule `fs:ro:/usr/lib`
- **THEN** entries with matched rule `fs:ro:/usr/lib` are highlighted
- **AND** entries with matched rule `fs:rw:/tmp` are not highlighted

#### Scenario: Leaving a rule clears highlights

- **WHEN** the user stops hovering over a rule
- **THEN** all entry highlights are removed

### Requirement: Hover log entry highlights matched rule

When an access log entry is hovered, the rule in the rules pane whose raw rule string equals the entry's matched rule SHALL be visually highlighted. Other rules SHALL NOT be highlighted.

#### Scenario: Hovering an entry highlights its rule

- **WHEN** the rules pane contains rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user hovers over a log entry with matched rule `fs:ro:/usr/lib`
- **THEN** the rule `fs:ro:/usr/lib` is highlighted in the rules pane
- **AND** the rule `fs:rw:/tmp` is not highlighted

#### Scenario: Hovering an unmatched entry highlights nothing

- **WHEN** the user hovers over a log entry with an empty matched rule
- **THEN** no rules are highlighted in the rules pane

#### Scenario: Leaving an entry clears rule highlights

- **WHEN** the user stops hovering over a log entry
- **THEN** all rule highlights are removed
