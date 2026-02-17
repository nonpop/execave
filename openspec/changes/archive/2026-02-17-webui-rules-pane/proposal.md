## Why

The web UI currently shows access log entries but not the rules that govern them. Users must mentally map entries back to their config file to understand which rule allowed or denied each access. Displaying the rules alongside the log is the foundation for the interactive config editing loop described in the web monitor-editor plan.

## What Changes

- Add a rules pane to the web UI that displays the current config rules alongside the access log table.
- The rules pane is read-only in this change (editing comes later).
- Restructure the page layout from single-column to two-pane (rules left, log right).
- Bidirectional hover-highlighting: hovering a rule highlights matching log entries; hovering a log entry highlights its matched rule.
- The server reads rules from the config passed at construction and serves them to the template.
- On SSE reconnect, the client reloads rules from the server because it may have reconnected to a new session with different rules.

## Playbooks

### New Playbooks

None.

### Modified Playbooks

- `iterating-config`: Add a use case for viewing rules alongside the access log during a monitored run.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: Add requirements for displaying config rules in a side pane, bidirectional hover-highlighting between rules and log entries, and refreshing rules on SSE reconnect.

## Impact

- `internal/webui/server.go`: Pass rules to the template data.
- `internal/webui/templates/index.html`: Two-pane layout with rules list and log table.
- `internal/webui/integration_test.go`: Test that rules appear in the rendered page.
- No new packages or dependencies.
- No security impact: rules are already loaded and trusted; this only adds read-only display of data the server already holds.
