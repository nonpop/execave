## Why

When execave runs a TUI application with `--monitor`, the web UI URL printed to stderr is hidden by the TUI's alternate screen buffer. If the browser also doesn't auto-open (SSH, headless, no xdg-open), there is no way to view the access log. A text-based log output to a file or stderr provides a non-browser fallback.

## What Changes

- **BREAKING**: `--monitor` flag changes from boolean to string. Bare `--monitor` still enables web UI (backward-compatible). `--monitor=<path>` writes text log to a file. `--monitor=-` writes text log to stderr (buffered until process exits to avoid interleaving). For files, entries are written immediately (tailable with `tail -f`).
- New `--show-allowed` flag (default: false) includes OK entries in output (by default only DENY/UNKNOWN shown).
- New `--show-nolog` flag (default: false) includes entries matching nolog rules (by default hidden).
- When using `--monitor` (web UI mode), `--show-allowed` and `--show-nolog` set the initial checkbox state for the "Denied only" and "Apply nolog rules" filters.
- Shared nolog resolution and path shortening logic extracted from webui to a new `internal/logfilter` package for reuse by the text log writer.

## Playbooks

### New Playbooks

(none)

### Modified Playbooks

- `monitoring-access`: New use cases for viewing access log as text output (file and stderr modes), and for controlling filter defaults via CLI flags.

## Capabilities

### New Capabilities

- `text-log`: Text-based access log writer that subscribes to the access logger, applies filtering (denied-only, nolog), shortens filesystem paths, and writes formatted entries to an `io.Writer`.

### Modified Capabilities

- `web-ui`: Filter checkboxes ("Denied only", "Apply nolog rules") accept initial state from server-side configuration instead of being hardcoded as checked.

## Impact

- `cmd/execave/main.go` — flag parsing, `runMonitored()` split into web/text paths
- `internal/logfilter/` — new package (extracted from webui: `ShortenPath`, `IsNolog`)
- `internal/textlog/` — new package (text log writer)
- `internal/webui/server.go` — use logfilter, accept `FilterDefaults`
- `internal/webui/shorten.go` — deleted (moved to logfilter)
- `internal/webui/templates/index.html` — dynamic checkbox initial state
- No security impact: text log is display-only (same data as web UI). No changes to permission checks, rule resolution, sandbox boundaries, config parsing, or bwrap invocation. The `--monitor` flag value is not passed to the sandbox or child process.
