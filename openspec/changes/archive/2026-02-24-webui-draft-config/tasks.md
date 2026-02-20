## 1. config.ParseTOML

- [x] 1.1 Add `ParseTOML(data []byte, configDir, configPath string, managedPaths []string) (*Config, error)` — extract TOML unmarshal + ParseRules call from Load into this new function
- [x] 1.2 Refactor `Load` to read the file and delegate to `ParseTOML`
- [x] 1.3 Unit tests for ParseTOML: valid TOML, empty bytes, invalid TOML, invalid rules, comments preserved through parsing
- [x] 1.4 Integration test: ParseTOML produces identical Config to Load for the same file content

## 2. proxy.SetResolver

- [x] 2.1 Change `Proxy.resolver` from `*netrules.Resolver` to `atomic.Pointer[netrules.Resolver]`; update `New`, `handleCONNECT`, and `handleHTTP` to use `.Store()` / `.Load()`
- [x] 2.2 Add `SetResolver(resolver *netrules.Resolver)` method with godoc
- [x] 2.3 Integration tests: SetResolver updates rules for subsequent requests (deny→allow, allow→deny, deny-all→allow)

## 3. webui server state model and constructor

- [x] 3.1 Replace `cfg *config.Config` and `port string` fields with `configPath`, `managedPaths`, `savedContent`, `draftContent`, `accessToken`, `OnConfigChange func(*config.Config)`, and `mu sync.Mutex`
- [x] 3.2 Change constructor from `New(rnr, cfg, command, port, homeDir, configDir)` to `New(rnr, command, homeDir, configDir, configPath, configContent, managedPaths)`; port is always `"0"`; generate accessToken alongside sessionID
- [x] 3.3 Update `handleIndex` template data: replace `Rules []string` with `Config string` (current draftContent)
- [x] 3.4 Update all unit test helpers (`StartServer`, `StartServerWithPaths`, `StartServerWithRunner`) for new constructor signature

## 4. webui access token authentication

- [x] 4.1 Add token-checking middleware that wraps all mux handlers; return 403 for missing or incorrect `?token=` parameter
- [x] 4.2 Update `URL()` to return `http://addr?token=TOKEN`
- [x] 4.3 Unit tests: valid token succeeds, missing token → 403, wrong token → 403, token required on all endpoints (/, /events, /api/start, /api/stop, /api/save, /api/revert)
- [x] 4.4 Update existing unit and integration tests to include token in all requests

## 5. webui endpoints (start-with-body, save, revert)

- [x] 5.1 Modify `handleStart`: read request body as raw TOML, update draftContent, parse via ParseTOML, if invalid → 400 with error, if valid → call OnConfigChange → runner.Start → 200
- [x] 5.2 Add `handleSave`: read body, parse via ParseTOML, if invalid → 400, if valid → write to configPath (0644) → update savedContent and draftContent → 200
- [x] 5.3 Add `handleRevert`: set draftContent = savedContent, return savedContent as text/plain → 200
- [x] 5.4 Register `/api/save` and `/api/revert` routes in Start()
- [x] 5.5 Unit tests: start with valid body, start with invalid body → 400, save valid → file written, save invalid → 400 + file unchanged, revert returns saved content
- [x] 5.6 Integration tests: start-with-body uses new config, save writes to temp file, revert resets draft, save invalid config rejected

## 6. webui SSE config event

- [x] 6.1 Replace `sendRulesEvent` with `sendConfigEvent` that sends `event: config` with JSON `{"draft": "...", "saved": "..."}`
- [x] 6.2 Update `handleEvents` to call `sendConfigEvent` instead of `sendRulesEvent`; event order: session → status → config → entries
- [x] 6.3 Unit tests: config event contains draft and saved fields, config event sent on SSE connect, draft and saved differ after start-with-edited-config
- [x] 6.4 Integration tests: config SSE event replaces rules SSE event, config event reflects draft/saved state after save, config event reflects draft/saved state after start

## 7. webui template (HTML/JS)

- [x] 7.1 Replace rules `<ul class="rules-list">` with `<textarea>` initialized from `{{.Config}}`
- [x] 7.2 Add error display area below textarea (hidden by default)
- [x] 7.3 Add "Save" and "Revert" buttons in the status bar
- [x] 7.4 JS: extract token from `window.location.search`, append `?token=...` to all fetch() URLs and EventSource URL
- [x] 7.5 JS: Start/Restart sends textarea content as POST body to `/api/start`; show error on 400
- [x] 7.6 JS: Save sends textarea content to `/api/save`; Revert calls `/api/revert` and updates textarea with response
- [x] 7.7 JS: handle `config` SSE event — set textarea.value from data.draft, track savedConfig from data.saved, update modified indicator and Revert button state
- [x] 7.8 JS: modified indicator — compare textarea content to savedConfig on input events; show/hide indicator, enable/disable Revert
- [x] 7.9 Remove hover-highlighting JS and CSS (mouseenter/mouseleave on rules and entries, data-rule attributes, highlight styles)
- [x] 7.10 Integration tests: config textarea renders on page load, textarea contains raw TOML content

## 8. CLI changes

- [x] 8.1 Change `--monitor` from string flag to boolean flag; remove `validateMonitorPort()` and `validatePort()`
- [x] 8.2 Add `--no-open` boolean flag
- [x] 8.3 In `runMonitored`: read raw config file content via `os.ReadFile(absConfigPath)`, pass to `webui.New` with new constructor signature
- [x] 8.4 Wire `server.OnConfigChange` to create a new resolver and call `httpProxy.SetResolver`
- [x] 8.5 After server starts: print URL (with token) to stderr; if `--no-open` is not set, call `exec.Command("xdg-open", url).Start()` (ignore errors)
- [x] 8.6 Update command examples and help text for `--monitor` (remove port references)

## 9. Cleanup and test updates

- [x] 9.1 Remove rules-pane integration tests (test for `<ul class="rules-list">`, rule display scenarios)
- [x] 9.2 Remove hover-highlighting integration tests
- [x] 9.3 Update existing SSE integration tests: replace rules-event expectations with config-event expectations
- [x] 9.4 Update existing E2E tests: change `--monitor=PORT` to `--monitor` in all test commands
- [x] 9.5 Run `golangci-lint run --fix` and fix any issues
