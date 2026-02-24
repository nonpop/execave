## Context

The access log currently stores and displays every access event (OK, DENY, UNKNOWN). In practice, most entries are noise — allowed reads to system paths, or expected denies from applications that tolerate write failures. Users need two filtering mechanisms: a global result-type filter (denied-only by default) and per-path/host log visibility rules (nolog/log) to suppress specific known entries.

Both filters are frontend-only (web UI display logic). The Logger continues to store all entries unconditionally, preserving the full audit trail for inspection when filters are toggled off.

## Goals / Non-Goals

**Goals:**
- Default web UI shows only DENY and UNKNOWN entries.
- Users can configure `fs:nolog:PATH` and `net:nolog:HOST:PORT` rules to suppress specific entries (including expected denies).
- Users can configure `fs:log:PATH` and `net:log:HOST:PORT` rules to override nolog for specific subtrees/endpoints.
- Log rules reuse the same syntax, parsing, validation, and resolution semantics as access rules.
- Both filters (mode toggle, nolog toggle) are independent frontend checkboxes; toggling them off reveals hidden entries.
- No security impact: log rules do not affect access enforcement, sandbox boundaries, or bwrap invocation.

**Non-Goals:**
- Persisting filter toggle state across page reloads (toggles reset to defaults).
- Per-operation-type nolog (e.g., suppress only WRITE denies). Nolog suppresses all result types for matching entries.
- Backend filtering — the Logger stores everything regardless of log rules.

## Decisions

### 1. Log rules live in fsrules and netrules packages

**Decision**: Add `log` and `nolog` as new "permission" types in fsrules and new "action" types in netrules, with dedicated parse/validate/resolve functions.

**Rationale**: Log rules share identical syntax and resolution semantics with access rules. fsrules log rules use the same path normalization (tilde expansion, relative path resolution, cleanup) and longest-prefix-match resolution. netrules log rules use the same target parsing (domain, wildcard, IPv4, IPv6, CIDR), port parsing, and single-dimension specificity resolution. Putting them in the same package avoids duplicating this logic.

**Alternative considered**: Separate `logrules` package. Rejected because it would duplicate path/target parsing and resolution algorithms, or require extracting shared code into yet another package.

**Implementation detail**: Log rules use separate types (`LogRule` in fsrules, `LogRule` in netrules) and separate resolvers (`LogResolver`), not the same `Rule`/`Resolver` types. This keeps access and log concerns clearly separated while sharing the same package and parsing utilities.

### 2. Log rule resolution is a separate resolver

**Decision**: Each package gets a `LogResolver` with a `Visible(path/host) bool` method, separate from the access `Resolver`.

**Rationale**: Access resolution and log resolution are orthogonal. Access resolution determines what's allowed; log resolution determines what's displayed. They use the same matching algorithm but operate independently. Keeping them as separate resolvers prevents coupling and makes the webui's filtering logic explicit: `logResolver.Visible(entry.Target)`.

### 3. Validation prevents duplicate paths/identities across log rules

**Decision**: `fsrules.ValidateLogRules` rejects duplicate paths in log rules. `netrules.ValidateLogRules` rejects duplicate (target, port) identities in log rules. Duplicates between access rules and log rules are fine (they're different namespaces).

**Rationale**: Duplicate log rules would create ambiguity (which wins?). But a path can have both an access rule (`fs:ro:/usr`) and a log rule (`fs:nolog:/usr`) — these serve different purposes and don't conflict.

### 4. Config struct gains log rule fields

**Decision**: `Config` gets `FSLogRules []fsrules.LogRule` and `NetLogRules []netrules.LogRule` fields. The config parser routes `fs:log:PATH` and `fs:nolog:PATH` to `fsrules.ParseLogRule`, and `net:log:HOST:PORT` and `net:nolog:HOST:PORT` to `netrules.ParseLogRule`.

**Rationale**: The existing `parseRules` function already splits on the first colon to get the resource prefix (`fs` or `net`), then passes the body to the appropriate parser. The body of a log rule starts with `log:` or `nolog:` — the per-package parser distinguishes log rules from access rules by the action/permission prefix.

### 5. Frontend filtering in the web UI

**Decision**: The web UI applies two independent filters when rendering entries:
1. **Mode filter**: If "Denied only" is checked (default: on), hide entries with `Result == OK`.
2. **Nolog filter**: If "Apply nolog rules" is checked (default: on), hide entries where the log rule resolver says "not visible".

Both filters must pass for an entry to be displayed. The filters are applied both on initial page render (server-side in Go template) and on SSE entry events (client-side in JavaScript).

**Rationale**: Server-side filtering on initial render avoids sending hidden entries in the HTML. Client-side filtering on SSE events avoids re-rendering the full page when toggles change — the JS just shows/hides existing DOM elements.

**Implementation detail**: Each SSE entry event includes a `nolog: true/false` field so the client knows whether the entry matches a nolog rule. The client applies the mode filter locally (it already has the `result` field). When a toggle is changed, the client iterates existing entries and shows/hides them — no server round-trip needed.

### 6. fsrules log rules reuse Parse internals

**Decision**: `fsrules.ParseLogRule(ruleBody, configDir)` reuses the same path normalization as `Parse` (tilde expansion, relative path resolution, filepath.Clean). The rule body format is `log:PATH` or `nolog:PATH`.

**Rationale**: Path handling is identical — only the "permission" differs (log visibility instead of access level).

### 7. netrules log rules reuse Parse internals

**Decision**: `netrules.ParseLogRule(ruleBody)` reuses the same target and port parsing as `Parse`. The rule body format is `log:TARGET:PORT` or `nolog:TARGET:PORT`.

**Rationale**: Target and port handling is identical — only the "action" differs (log visibility instead of protocol allowance).

## Risks / Trade-offs

**[Risk: Nolog hides unexpected denies]** → A `fs:nolog:/some/dir` rule suppresses ALL entries under that subtree, including future denies from child `fs:none:` rules. **Mitigation**: Users can uncheck "Apply nolog rules" at any time to see suppressed entries. The `fs:log:` override allows carving out visible sub-paths.

**[Risk: SSE event size increase]** → Each entry event gains a `nolog` boolean field. **Mitigation**: Negligible — one additional JSON field per event.

**[Risk: Frontend state complexity]** → Two independent toggles with per-entry metadata. **Mitigation**: Entries are stored in the DOM; show/hide is a CSS class toggle. No complex state management needed.
