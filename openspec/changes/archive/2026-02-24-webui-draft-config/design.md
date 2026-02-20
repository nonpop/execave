## Context

The web UI currently takes a static `*config.Config` at construction and never updates it. The rules pane is read-only; Start/Restart always use the original config. To iterate on rules, users must edit the file externally, restart the CLI process, and reload the browser.

This design enables an **edit → run → observe → save** loop inside the web UI by making the raw TOML config editable in a textarea, parsing it on Start, and optionally writing it back to disk.

The change touches four packages: `config` (new `ParseTOML`), `proxy` (new `SetResolver`), `webui` (server state, endpoints, UI), and `cmd/execave` (CLI flags, wiring).

## Goals / Non-Goals

**Goals:**
- Users can edit, run-against, save, and revert config entirely within the web UI
- Config validation prevents starting runs or saving invalid configs
- Proxy net rules are updated atomically before each UI-triggered run
- Access token prevents unauthorized use when port is accidentally exposed
- Existing non-monitor code paths are unaffected

**Non-Goals:**
- Multi-tab synchronization (last action wins)
- Syntax highlighting or TOML-aware editing in the textarea
- Undo/redo beyond single-level revert-to-saved
- File watching for external edits

## Decisions

### 1. `config.ParseTOML(data []byte, configDir, configPath string, managedPaths []string) (*Config, error)`

Extract the TOML-unmarshal + `ParseRules` call from `Load` into a new exported function. `Load` becomes: read file → `ParseTOML`.

**Why**: The webui needs to parse user-edited TOML without writing to a temp file. `ParseRules` takes `[]string` rule slices; `ParseTOML` takes raw bytes — the webui has bytes (textarea content), not pre-extracted rule strings.

**Alternative considered**: Have the webui parse TOML itself and call `ParseRules` directly. Rejected because it duplicates the TOML struct definition and couples the webui to the config file format.

### 2. `proxy.SetResolver(resolver *netrules.Resolver)`

Change the proxy's `resolver` field from `*netrules.Resolver` to `atomic.Pointer[netrules.Resolver]`. Add `SetResolver` that calls `.Store()`. Update `handleCONNECT` and `handleHTTP` to use `.Load()`.

**Why**: When the user edits net rules in the textarea and clicks Start, the proxy must enforce the new rules immediately. Without this, stale rules would persist from the previous config.

**Pattern**: Mirrors the existing `SetLogger` / `atomic.Pointer[accesslog.Logger]` pattern. Same concurrency model: atomic swap is safe against in-flight requests.

**Atomicity guarantee**: `SetResolver` is called before `runner.Start`, so by the time the new run's first network request reaches the proxy, the new resolver is already in place. There is no window of stale rules.

### 3. Server state model

Replace the immutable `cfg *config.Config` field with mutable draft/saved content:

```
Remove:  cfg        *config.Config
         port       string

Add:     configPath   string       // absolute path for ParseTOML + file writes
         managedPaths []string     // for ParseTOML
         mu           sync.Mutex   // guards savedContent, draftContent
         savedContent string       // file content at startup or after last Save
         draftContent string       // updated by Start (from request body) and Revert
         accessToken  string       // random hex, required on every HTTP request
         OnConfigChange func(*config.Config)  // called on successful Start parse
```

Both `savedContent` and `draftContent` are initialized to the file content read at startup by `cmd/execave/main.go`. The constructor changes from `New(rnr, cfg, command, port, homeDir, configDir)` to `New(rnr, command, homeDir, configDir, configPath, configContent, managedPaths)`.

Port is always `"0"` (OS-assigned random port). The `accessToken` is a second random hex string generated alongside the existing `sessionID`.

**Why `draftContent` is updated on Start, not on every keystroke**: The server does not receive textarea edits in real-time. It only learns the draft content when the user clicks Start (or Save). This is simpler and avoids WebSocket/debounce complexity. The `config` SSE event sends both draft and saved on reconnect to restore the textarea after connection drops.

**Why `sync.Mutex` instead of `atomic.Pointer[string]`**: Draft and saved content must be read together atomically (for the `config` SSE event and the modified-indicator comparison). A mutex around the pair is simpler than two atomics with a generation counter.

### 4. Access token (Jupyter Notebook pattern)

Every HTTP request must include `?token=<hex>` in the query string. The token is:
- Generated at server construction (16 random bytes → 32 hex chars)
- Included in the URL printed to stderr: `execave: monitor running at http://127.0.0.1:PORT?token=TOKEN`
- Passed to `xdg-open` for browser auto-open
- Extracted by the JS client from `window.location.search` and appended to all fetch/EventSource URLs

Requests without a valid token receive 403 Forbidden (plain text, no body details).

**Threat model**: The primary threat is accidental exposure — the user forwards the port via SSH tunnel, reverse proxy, or the machine is multi-user. Random port alone is insufficient (port scanning). The token ensures that knowing the port is not enough. An attacker must also obtain the token, which is only available from the process's stderr output or the browser's URL bar.

**What the token does NOT protect against**: A local process that can read `/proc/<pid>/cmdline` or the terminal scrollback. This is acceptable — local root-equivalent attackers are out of scope (see docs/security-model.md: "No protection against privileged attackers").

**Alternative considered**: Cookie-based auth with a login page. Rejected as overengineered for a localhost dev tool. The URL-token pattern is well-established (Jupyter Notebook) and requires zero user interaction.

### 5. API endpoint changes

**`POST /api/start`** — Request body is raw TOML text (not JSON). Flow:
1. Read body → store as `draftContent`
2. Parse via `config.ParseTOML(body, configDir, configPath, managedPaths)`
3. If invalid → 400 with error text; draft is still updated (user can fix and retry)
4. If valid → `OnConfigChange(cfg)` → `runner.Start(ctx, cfg, command)` → 200

**Why draft is updated even on validation failure**: The draft represents what's in the textarea. If Start fails due to invalid config, the user fixes the error and retries. On SSE reconnect, the server should restore the textarea to what the user last submitted, not what last succeeded.

**`POST /api/save`** — Request body is raw TOML text. Flow:
1. Read body → parse via `ParseTOML`
2. If invalid → 400 with error text (don't save broken config to disk)
3. Write to `configPath` (0644) → update both `savedContent` and `draftContent` → 200

**`POST /api/revert`** — No request body. Sets `draftContent = savedContent`. Returns `savedContent` as `text/plain`.

**`POST /api/stop`** — Unchanged.

### 6. SSE `config` event (replaces `rules`)

The `rules` SSE event is replaced by `config`:
```json
{"draft": "<full TOML text>", "saved": "<full TOML text>"}
```

Sent on every SSE connect/reconnect (in the initial burst: session → status → config → entries). The client uses `draft` to populate the textarea and compares `draft === saved` to drive the modified indicator and Revert button state.

**Why both fields**: The client needs `saved` to compute the modified state. Sending both avoids a separate endpoint and keeps the client stateless on reconnect.

### 7. `OnConfigChange` callback for proxy updates

The webui server exposes an `OnConfigChange func(*config.Config)` field (matching the runner's `OnLoggerChange` pattern). `cmd/execave/main.go` wires it:

```go
server.OnConfigChange = func(cfg *config.Config) {
    if httpProxy != nil {
        httpProxy.SetResolver(netrules.NewResolver(cfg.NetRules))
    }
}
```

**Why a callback instead of direct proxy dependency**: The webui package should not import `proxy`. The callback keeps the dependency inversion: `main.go` wires the components, each package stays decoupled.

### 8. CLI changes

`--monitor` changes from `--monitor=PORT` (string flag) to `--monitor` (boolean flag). The port is always OS-assigned (port 0). `validateMonitorPort()` is removed.

New `--no-open` flag (boolean, default false). When `--monitor` is set and `--no-open` is not, `xdg-open <url>` is called after the server starts. Errors from `xdg-open` are ignored (e.g., headless server, no display).

**Why always random port**: Fixed ports cause "address in use" errors when restarting quickly. Random ports eliminate this friction. The URL is printed to stderr and auto-opened in the browser, so the user never needs to remember the port.

### 9. UI changes

The left pane's `<ul class="rules-list">` is replaced with:
- `<textarea>` containing the raw TOML config
- Error display area below the textarea (hidden by default, shown on 400 responses)
- "Save" and "Revert" buttons in the status bar alongside existing Start/Stop

The JS client:
- Extracts token from URL: `new URLSearchParams(window.location.search).get('token')`
- Appends `?token=...` to all fetch() URLs and the EventSource URL
- Start/Restart: POST `/api/start?token=...` with textarea content as body
- Save: POST `/api/save?token=...` with textarea content as body
- Revert: POST `/api/revert?token=...`; updates textarea with response body
- `config` SSE handler: sets `textarea.value = data.draft`, updates modified indicator

Bidirectional hover highlighting is removed (rules `<li>` elements no longer exist). The matched rule for each log entry remains visible as a tooltip on the row.

## Risks / Trade-offs

**[Config mutation over HTTP]** → Mitigated by random port + access token. See Decision 4 for threat analysis. Residual risk: local processes with access to stderr output or `/proc` can obtain the token. This is acceptable per the existing threat model ("no protection against privileged attackers").

**[Stale proxy rules after config edit]** → Mitigated by calling `SetResolver` before `runner.Start`. The atomic swap ensures no in-flight request sees the old resolver after Start returns. See Decision 2.

**[Invalid config saved to disk]** → Mitigated by ParseTOML validation on both Start and Save. Invalid configs are rejected with 400; they cannot be saved to disk or used to start runs.

**[Multi-tab editing]** → Not addressed in v1. Two tabs editing simultaneously is unsupported — last Start/Save action wins. The `config` SSE event syncs state on connect but does not broadcast mid-session textarea changes.

**[File write is non-atomic]** → Save uses `os.WriteFile` (truncate + write), not write-to-temp + rename. A crash mid-write could corrupt the config file. Acceptable for v1: the config file is small, the user is intentionally saving, and atomic file writes add complexity for a localhost dev tool. Can be upgraded to write+rename if needed.

**[Breaking SSE clients]** → The `rules` event is replaced by `config`. No external consumers exist (internal API), so the break is safe.
