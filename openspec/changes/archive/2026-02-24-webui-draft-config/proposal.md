## Why

The web UI currently shows a read-only rules pane and always runs with the static config loaded at startup. Users must manually edit the config file, restart execave, and reload the browser to see the effect of config changes. This change introduces an **edit → run → observe → save** loop directly in the web UI: the user edits their raw TOML config in a textarea, starts/restarts the sandboxed command against the edited config, observes the access log, and saves to disk when satisfied.

## What Changes

- **BREAKING**: `--monitor` becomes a boolean flag (no port argument). The server always binds to a random OS-assigned port.
- A random access token is generated at startup. The server requires it (as a `?token=` query parameter) on every request — GET, POST, and SSE. Requests without a valid token receive 403.
- The server prints the full URL including the token to stderr: `execave: monitor running at http://127.0.0.1:54321?token=abc123...`
- The browser is auto-opened to the URL via `xdg-open`. A `--no-open` flag disables this.
- The rules pane is replaced with an editable textarea containing the raw TOML config file (verbatim, with comments).
- POST /api/start accepts the textarea content, parses it as TOML, validates, and runs the sandbox against the parsed config.
- New POST /api/save endpoint validates and writes the textarea content to the original config file.
- New POST /api/revert endpoint resets the textarea to the last-saved content.
- The SSE `rules` event is **replaced** with a `config` event that sends both the current draft and the last-saved content (JSON `{"draft": "...", "saved": "..."}`), enabling the client to show a "Modified" indicator and sync on reconnect.
- The proxy gains a `SetResolver` method so that updated net rules take effect immediately when a new run starts.
- A new `config.ParseTOML` function extracts TOML parsing from `config.Load` for in-memory use.
- **BREAKING**: The `rules` SSE event is replaced by `config`. Existing SSE clients expecting `rules` will need to update.
- Bidirectional hover highlighting between rules and log entries is removed (incompatible with textarea; matched rule remains visible as tooltip on each log row).

## Playbooks

### New Playbooks

_None._

### Modified Playbooks

- `iterating-config`: Add use cases for editing config in the web UI, saving to disk, and reverting. Existing restart/view use cases change because config is now editable in the UI rather than read-only.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `web-ui`: Replace "Rules pane" and "Rules refreshed on SSE reconnect" requirements with config editor textarea, `config` SSE event, save/revert endpoints, and modified indicator. Modify "Run control endpoints" to accept config content in the start request body. Remove hover highlight requirements (rules pane no longer exists). Add access token requirement for all requests. Change port binding to always use random OS-assigned port.
- `config`: Add `ParseTOML` requirement (parse from bytes, same validation as `Load`/`ParseRules`).
- `proxy`: Add `SetResolver` requirement (atomic resolver swap at runtime, matching `SetLogger` pattern).

## Impact

- **Packages modified**: `internal/webui`, `internal/config`, `internal/proxy`, `cmd/execave`
- **CLI**: `--monitor=PORT` becomes `--monitor` (boolean). New `--no-open` flag to suppress auto-opening the browser.
- **Security**:
  - **Config mutation via HTTP — mitigated by token auth**: This change adds the ability to edit sandbox security rules and write to the user's config file via HTTP. Every request (GET, POST, SSE) requires a random access token generated at startup. The token is only revealed via the URL printed to the console (and passed to the browser via `xdg-open`). Combined with random port assignment, an attacker must know both the port and the token to access the server — port scanning alone is insufficient. This protects against accidental exposure (reverse proxy, SSH tunnel) and local process attacks (cannot guess the token).
  - Config validation is enforced on both Start and Save — invalid configs cannot start runs or be saved to disk.
  - The proxy's net rules are updated atomically before each run via `SetResolver`, so there is no window where stale rules apply.
- **Backward compatibility**: The SSE `rules` event is replaced by `config`. The webui.New constructor signature changes (replaces `cfg *config.Config` with raw file content + config path). These are internal APIs with no external consumers.
