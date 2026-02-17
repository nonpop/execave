## ADDED Use Cases

### Use Case: View rules alongside the access log

The user views their config rules in the web UI while observing access log entries, so they can understand which rules govern which accesses without switching to their editor.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **WHEN** the user opens the web UI
- **THEN** the page displays the rules `fs:ro:/usr/lib` and `fs:rw:/tmp` in a rules pane
- **AND** the access log entries are displayed alongside in a separate pane

### Use Case: Rules update after restarting execave with a new config

The user edits their config, restarts execave, and the browser tab automatically shows the updated rules without a manual page refresh.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the web UI is open in a browser tab showing those rules
- **WHEN** the user stops execave, adds rule `net:allow:example.com:443`, and restarts execave on the same port
- **THEN** the browser tab reconnects and the rules pane displays `fs:ro:/usr/lib`, `fs:rw:/tmp`, and `net:allow:example.com:443`
- **AND** the previously displayed rules are replaced (no stale rules shown)

### Use Case: Hover a rule to see matching log entries

The user hovers over a rule to see which access log entries it matched, making it easy to understand what a rule governs.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the access log contains entries matched by `fs:ro:/usr/lib`
- **WHEN** the user hovers over the rule `fs:ro:/usr/lib` in the rules pane
- **THEN** the log entries whose matched rule is `fs:ro:/usr/lib` are highlighted
- **AND** log entries matched by other rules are not highlighted

### Use Case: Hover a log entry to see its matched rule

The user hovers over an access log entry to see which rule allowed or denied it.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor=9876 -- ls /usr/lib`
- **AND** the access log contains an entry matched by `fs:ro:/usr/lib`
- **WHEN** the user hovers over that log entry
- **THEN** the rule `fs:ro:/usr/lib` is highlighted in the rules pane
- **AND** other rules are not highlighted
