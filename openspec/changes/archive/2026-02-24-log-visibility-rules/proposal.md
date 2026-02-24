## Why

The access log currently shows every filesystem and network access (after dedup and managed-path filtering). In practice, most entries are allowed reads to system paths — noise that buries the interesting signal: denied accesses. Additionally, some denies are expected and harmless (e.g., an app always tries to write to a read-only directory, fails, and continues fine), but they clutter the log on every run.

Users need two things: (1) a default view that shows only denies and unknowns, and (2) per-path/host rules to suppress specific entries they've already reviewed and decided to tolerate.

## What Changes

- Add `fs:log:PATH` and `fs:nolog:PATH` rule types for filesystem log visibility, using the same longest-prefix-match resolution as access rules.
- Add `net:log:HOST:PORT` and `net:nolog:HOST:PORT` rule types for network log visibility, using the same specificity resolution as access rules. Supports the same target patterns (domain, wildcard domain, IPv4, IPv6, CIDR) and port patterns (number or `*`).
- Default (no matching log rule) = show the entry.
- Add a "denied only" frontend toggle in the web UI (default: on) that hides OK entries.
- Add an "apply nolog rules" frontend toggle in the web UI (default: on) that applies log/nolog filtering; unchecking shows suppressed entries.
- Both filters are independent — an entry must pass both to be displayed.
- Config format is backward-compatible: existing configs with no log/nolog rules behave identically (all entries stored, denied-only shown by default in UI).

**Security impact**: Log/nolog rules do NOT affect access enforcement — they only control display filtering in the web UI. All entries are still stored in the Logger and available for inspection (by unchecking the toggle). The sandbox boundary, rule resolution, and bwrap invocation are unaffected.

## Playbooks

### New Playbooks

(none)

### Modified Playbooks

- `monitoring-access`: Add use cases for log visibility rules (nolog/log, toggles, specificity). Modify "View access log in web UI" to reflect denied-only default.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `fs-rules`: Add `log` and `nolog` as log-visibility rule types alongside existing access permissions (`ro`, `rw`, `none`). Same parsing (path normalization, tilde expansion, relative resolution), same validation (no duplicate paths across log rules), same longest-prefix-match resolution. Separate resolver for log visibility.
- `net-rules`: Add `log` and `nolog` as log-visibility rule types alongside existing access actions (`https`, `http`, `none`). Same parsing (target patterns, port patterns), same validation (no duplicate identity across log rules), same specificity resolution. Separate resolver for log visibility.
- `config`: Parsing and routing `fs:log`, `fs:nolog`, `net:log`, `net:nolog` rule bodies to fsrules and netrules respectively.
- `web-ui`: Frontend filter toggles (denied-only mode, nolog rule application) and log rule resolution for display filtering.

## Impact

- `internal/fsrules/`: New log rule type, parser, validator, and resolver reusing existing path matching.
- `internal/netrules/`: New log rule type, parser, validator, and resolver reusing existing target matching.
- `internal/config/`: Rule parsing extended with four new action types routed to existing packages. Config struct gains FSLogRules and NetLogRules fields.
- `internal/webui/`: Two new UI toggles, frontend filtering logic, log rule resolver integration.
- Config format: Additive only — no breaking changes.
