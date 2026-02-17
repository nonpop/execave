## 1. Backend: pass rules to template

- [x] 1.1 Extract raw rule strings from `cfg.FSRules` and `cfg.NetRules` (via `RawRule` fields) in `Server` and include them in the `handleIndex` template data.
- [x] 1.2 Add integration tests for the "Rules pane" spec scenarios: rules displayed on page load, empty rules, both fs and net rules.

## 2. Backend: send rules via SSE

- [x] 2.1 Add `sendRulesEvent` method to `Server` that writes a `rules` SSE event containing a JSON array of raw rule strings.
- [x] 2.2 Call `sendRulesEvent` in `handleEvents` alongside `sendSessionEvent` and `sendStatusEvent` at the start of each SSE connection.
- [x] 2.3 Add integration tests: rules event sent on SSE connect, correct JSON array content.

## 3. Template: two-pane layout with rules list

- [x] 3.1 Restructure `index.html` from single-column to two-pane flexbox layout (rules pane left, log pane right).
- [x] 3.2 Render the rules list in the left pane with `data-rule` attributes on each rule element.
- [x] 3.3 Add `data-rule` attributes to server-rendered log entry `<tr>` elements.

## 4. SSE: data-rule on dynamic entries

- [x] 4.1 Set `row.dataset.rule = entry.rule` when creating log entry rows from SSE events in the JS entry handler.

## 5. Client: refresh rules pane from SSE rules event

- [x] 5.1 Add `rules` event listener to EventSource that replaces the rules pane `<ul>` content with `<li>` elements from the received JSON array, setting `data-rule` attributes and re-attaching hover listeners.

## 6. Hover highlighting

- [x] 6.1 Add CSS class for highlight state (e.g. `.highlight`).
- [x] 6.2 Add `mouseenter`/`mouseleave` JS listeners on rule elements: on hover, `querySelectorAll` matching `data-rule` rows and add highlight class; on leave, remove all highlights.
- [x] 6.3 Add `mouseenter`/`mouseleave` JS listeners on log entry rows: on hover, find rule element with matching `data-rule` and add highlight class; on leave, remove all highlights. Skip for entries with empty `data-rule`.

## 7. E2E test

- [x] 7.1 Add E2E test for the "View rules alongside the access log" playbook use case: start execave with rules, verify the web UI page contains both the rules pane and access log entries.
