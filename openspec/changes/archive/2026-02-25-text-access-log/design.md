## Context

The web UI is the only way to view the access log. When a TUI app covers the terminal, the URL printed to stderr is hidden. If the browser doesn't auto-open (SSH, headless, no xdg-open), there's no fallback. The access logger already has a pub/sub system that makes adding new consumers straightforward.

Current architecture: `accesslog.Logger` → `webui.Server` (sole consumer via SSE). Nolog resolution and path shortening live in `webui` as unexported helpers.

## Goals / Non-Goals

**Goals:**
- Text-based access log output to file (real-time, tailable) or stderr (buffered until process exit)
- Same filtering semantics as web UI (denied-only default, nolog hidden by default)
- CLI flags to control filter defaults, shared between text and web UI modes
- Extract shared display logic (nolog resolution, path shortening) for reuse

**Non-Goals:**
- Combined web UI + text log in the same invocation (one mode at a time)
- Interactive filtering in text mode (filters are set at startup via flags)
- Timestamps in text output (entries are already deduplicated; timestamps add noise)
- Port-selection syntax for `--monitor` (orthogonal feature)

## Decisions

### D1: Overload `--monitor` flag (string with NoOptDefVal)

Change `--monitor` from `BoolVar` to `StringVar` with pflag `NoOptDefVal = "web"`.

- `--monitor` (no value) → `"web"` — web UI (backward-compatible)
- `--monitor=<path>` → file path — text log to file
- `--monitor=-` → `"-"` — text log to stderr

**Why not a separate `--log` flag?** The user prefers a single flag. `--monitor` already means "enable monitoring" — the value selects the output channel. This avoids two flags for a single concept.

**Breaking:** `--monitor=true`/`--monitor=false` (pflag bool syntax) would be interpreted as file paths. This was never documented usage; `--monitor` without a value was the standard invocation.

### D2: Stderr mode buffers until process exit

When `--monitor=-`, entries are written to a `bytes.Buffer` during execution. After the sandboxed process exits and the terminal is restored, the buffer is flushed to `os.Stderr`.

**Why?** Writing to stderr during TUI execution would corrupt the display. For non-TUI commands (web servers), file mode (`--monitor=access.log`) with `tail -f` is the better choice. Stderr mode is for quick one-shot commands where you want to see the log after exit.

### D3: New `internal/logfilter` package for shared logic

Extract from `webui`:
- `ShortenPath(absPath, homeDir, configDir string) string` — from `webui/shorten.go`
- `IsNolog(entry accesslog.Entry, fsRes *fsrules.LogResolver, netRes *netrules.LogResolver) bool` — from `webui.Server.isNolog()`

**Why a new package?** Both `webui` and `textlog` need identical nolog resolution. Duplicating ~25 lines risks divergence in a security tool. A thin shared package keeps the logic in sync. `accesslog` is a pure storage layer — adding `fsrules`/`netrules` dependencies would change its character.

### D4: New `internal/textlog` package

`Writer` type subscribing to `accesslog.Logger`:
- `New(out io.Writer, homeDir, configDir string, showAllowed, showNolog bool, fsRes, netRes)` — constructor
- `Run(ctx context.Context, logger *accesslog.Logger)` — blocking subscribe loop
- Formats each entry as: `%-7s %-5s  %s  (%s)\n` → `DENY    READ   ~/.ssh/id_rsa  (no-matching-rule)`

The writer tracks a `lastSeen` index. On each notification, it calls `logger.Entries()` and writes entries from `lastSeen` onward. On `ctx.Done()`, performs a final drain.

### D5: FilterDefaults for web UI initial checkbox state

Add `FilterDefaults` struct to `webui` package with `ShowAllowed` and `ShowNolog` bools. Passed to `webui.New()`. Template renders checkbox `checked` attribute conditionally:
- `DeniedOnlyChecked: !defaults.ShowAllowed`
- `ApplyNologChecked: !defaults.ShowNolog`

### D6: Split `runMonitored()` into web/text paths

`runMonitored()` becomes shared setup (runner, proxy wiring, log resolvers), then dispatches:
- `monitorMode == "web"` → `runMonitoredWeb()` — current flow
- Otherwise → `runMonitoredText()` — opens file or buffer, creates writer, runs single execution

## Risks / Trade-offs

**[Stderr with TUI apps]** → `--monitor=-` output is buffered until exit. For TUI apps, file mode is recommended. Documented in flag help text.

**[No combined web+text mode]** → One mode per invocation. If both are needed, the user can run with `--monitor` (web) and script the browser, or use `--monitor=file` and a separate viewer. This avoids complexity in the first iteration.

**[NoOptDefVal backward compat]** → `--monitor=true` changes meaning from "enable" to "write to file `true`". This was never documented usage. The bare `--monitor` syntax is preserved.

**[File creation failure]** → `--monitor=<path>` uses `os.Create`. Failure is reported as a startup error before the sandbox runs, same as config load failure.
