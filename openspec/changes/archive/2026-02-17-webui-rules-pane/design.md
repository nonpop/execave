## Context

The web UI (`internal/webui`) currently shows a single-column access log table with start/stop controls. The `Server` receives a `*config.Config` at construction, which holds parsed `FSRules` and `NetRules` — each with a `RawRule` string preserving the original config text (e.g. `"fs:ro:/usr/lib"`). Access log entries also carry a `Rule` field with the same raw string when matched.

The config is immutable for this change — the server displays rules but does not modify them.

## Goals / Non-Goals

**Goals:**
- Display all config rules (fs + net) in a left pane alongside the access log table.
- Bidirectional hover-highlighting between rules and log entries using the shared `RawRule`/`Rule` string as the join key.
- Lay the groundwork for future config editing by establishing the two-pane layout.

**Non-Goals:**
- Config editing, validation, or save semantics (future change).
- Click-to-filter or persistent selection (hover only).
- Separate treatment of fs vs net rules in the UI (displayed as a flat list in config order).

## Decisions

### 1. Extract raw rule strings from parsed Config

The `Config` struct holds `[]fsrules.Rule` and `[]netrules.Rule` but not the original `[]string`. Each parsed rule has a `RawRule` field. The server will reconstruct the display list by iterating fs rules then net rules and collecting `RawRule` values. This preserves config order within each rule type.

Alternative: Store raw `[]string` on Config. Rejected because it duplicates data and the parsed rules already carry the originals. If config editing is added later, storing raw strings on Config may become necessary, but that's a separate change.

### 2. Two-pane CSS layout with no JS framework

Use CSS flexbox for the two-pane layout: rules pane (fixed-width left) and log pane (flex-grow right). This matches the existing approach of server-rendered HTML with minimal vanilla JS.

Alternative: CSS Grid. Flexbox is simpler for a two-column split and sufficient here.

### 3. Hover-highlighting via data attributes and CSS classes

Each rule element gets a `data-rule` attribute with the raw rule string. Each log entry `<tr>` also gets a `data-rule` attribute from the entry's `Rule` field.

JS event listeners on `mouseenter`/`mouseleave`:
- On rule hover: add a CSS class to all `<tr>` elements whose `data-rule` matches.
- On entry hover: add a CSS class to the rule element whose `data-rule` matches.
- On mouse leave: remove all highlight classes.

New entries arriving via SSE get `data-rule` attributes set during DOM construction (already done via `ruleCell.textContent = entry.rule` — add `row.dataset.rule = entry.rule`).

Alternative: Use `entry.rule` to look up by iterating and comparing textContent. Rejected — `data-rule` attributes are explicit, O(1) queryable via `querySelectorAll`, and don't break if display formatting changes later.

### 4. Rules refreshed on SSE reconnect via `rules` SSE event

The server sends a `rules` SSE event containing the current config rules as a JSON array of raw rule strings. This event is sent alongside the `session` and `status` events at the start of each SSE connection.

When the client receives a `rules` event, it replaces the rules pane content with the new rules list and re-attaches hover listeners. This handles two reconnection scenarios:

1. **Cross-session reconnect** — EventSource auto-reconnects to a different server instance (e.g. execave was restarted with a different config). The new session may have different rules.
2. **In-session restart** — The user clicks Start/Restart, which creates a new run. The config is immutable within a server, so rules won't change in this case, but sending the event is harmless and keeps the protocol uniform.

Alternative: Fetch rules via a `/api/rules` REST endpoint on session change. Rejected because the SSE stream already handles session transitions for entries and status — adding rules to the same stream keeps all reconnection logic in one place and avoids a separate HTTP round-trip.

### 5. Entries with no matched rule

Entries with `Result=UNKNOWN` or empty `Rule` field won't participate in highlighting. Hovering them highlights nothing in the rules pane. Hovering a rule won't highlight them. This is correct: unmatched entries have no rule association.

## Risks / Trade-offs

**Large rule count performance** — `querySelectorAll('[data-rule="..."]')` scans all rows on each hover. With thousands of log entries this could lag. → Acceptable for v1; the monitor UI is for interactive iteration, not production log analysis. If needed later, a JS index (Map from rule string to row Set) can replace the DOM query.

**Rule string as join key** — The raw rule string must be identical between `fsrules.Rule.RawRule` / `netrules.Rule.RawRule` and `accesslog.Entry.Rule`. This is already the case: the resolver sets `Entry.Rule` from `Rule.RawRule`. No new coupling introduced.

**Layout shift on narrow viewports** — Two fixed panes may not work well on very narrow screens. → Acceptable: this is a localhost dev tool, not a responsive web app. No mobile support needed.
