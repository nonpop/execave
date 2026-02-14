# Web Monitor-Editor Loop in `--monitor` Mode

## Summary
Replace current plain `--monitor` behavior with a local web UI workflow that lets users:
1. Load current config (`rules`) as editable draft.
2. Start/stop/restart sandboxed runs against draft config (without saving).
3. See per-run access logs with bidirectional rule matching (`OK/DENY` to rules).
4. Save to the original config path when satisfied.

The UI is localhost-only, server-rendered with minimal JS, session-only history, and no stdout/stderr display.

## Public API / Interface Changes
1. CLI change (breaking by request):
- `--monitor` now launches web UI mode instead of writing plain monitor log files.
- Existing log-file monitor workflow via `--monitor [path]` is removed.
- Startup command is still passed after `--` and used as initial run target, with UI override support.

2. Runtime UI interface (local HTTP, internal contract):
- `GET /` serves the app shell.
- JSON endpoints for state, draft updates, run control, and save.

3. Config behavior:
- UI v1 edits `rules` only.
- Unknown top-level JSON fields are preserved on save.
- Save always writes back to launched config path.

## Implementation Plan

### 1. CLI and Mode Routing
1. Change Cobra `--monitor` flag semantics to UI mode trigger.
2. Require/parse startup command after `--` for initial command value.
3. In monitor mode, start local HTTP server bound to `127.0.0.1` on an available port and print URL to stderr/stdout (no auto-open).

### 2. Web UI Backend (`internal/webui`)
1. Add `Server` with in-memory session state:
- `config_path`
- `saved_config_doc` (full JSON document model for preserving unknown fields)
- `draft_rules`
- `initial_command` + `command_override`
- `runs[]` history (per-run tabs, in memory only)
- `active_run` handle (cancel func + status)

2. Thread safety:
- Guard mutable state with `sync.Mutex`.
- Snapshot draft at run start so edits during run apply only to next run.

### 3. Draft Config Editing + Validation
1. Add config helper APIs to parse/validate rules from in-memory draft (not file-only path).
2. Support two edit modes:
- Structured rule builder (`permission`, `path`)
- Raw JSON editor (for `rules` array view) with round-trip validation
3. Validation policy:
- If invalid, block `Run` and `Save`.
- Return field-level/file-level errors to UI.

### 4. Run Engine Integration
1. For each run:
- Build validated config from draft snapshot.
- Execute monitored sandbox run in-process using existing sandbox+monitor packages.
- Always run with monitoring enabled.
2. Run controls:
- `Start` (if none active)
- `Stop` (cancel context; process gets terminated)
- `Restart` (stop active then start new run with current draft snapshot)
3. Run output:
- Do not surface stdout/stderr in UI.
- Show run lifecycle state and exit code/error status only.

### 5. Access Log Capture and Rule Matching
1. Capture structured log entries in memory per run (not from disk files).
2. Keep full log (no truncation/pagination in v1).
3. Build indexes for bidirectional UX:
- Rule -> matching `OK/DENY` entries
- Entry -> matched rule (or unmatched category)
4. UNKNOWN handling:
- Show in separate unmatched category with reason.
- Do not associate UNKNOWN entries with rules.
5. Keep runs as separate tabs (timestamp + command + exit status).

### 6. Save Semantics
1. Save writes canonical pretty JSON to the original config path.
2. Preserve rule order from draft; canonical whitespace formatting.
3. External file-change handling:
- Detect mtime/hash drift since load/save baseline.
- Show non-blocking warning.
- Still allow/perform save (overwrite with current draft), then update baseline.

### 7. Frontend UX (Server-rendered + Minimal JS)
1. Main layout panes:
- Left: config editor (rule builder + raw JSON toggle)
- Center: run controls/status + command override
- Right: run tabs and access log table
2. Matching interactions:
- Click log row -> highlight matched rule.
- Click rule -> filter/highlight matching log rows.
3. No process output panel.
4. Draft persists across browser refresh while server is running.

### 8. Specs/Docs
1. Update `README.md` monitor section to describe web workflow and breaking change.
2. Update architecture docs for new `internal/webui` component and data flow.
3. Add/update OpenSpec artifacts for:
- Monitor mode behavior change
- UI capability requirements and scenarios.

## Test Cases and Scenarios

1. CLI behavior:
- `execave --monitor -- <cmd>` starts localhost UI and prints URL.
- Legacy monitor path usage is rejected or treated per new semantics consistently.

2. Validation gating:
- Invalid draft blocks Run and Save with clear error payload.

3. Run lifecycle:
- Start run creates new tab with config snapshot.
- Stop cancels active run.
- Restart creates a new run using latest draft.
- Edits during active run do not mutate that run’s snapshot.

4. Matching behavior:
- `OK/DENY` rows map correctly to raw rules.
- Rule-click filters/highlights correct rows.
- UNKNOWN rows appear under unmatched with reason.

5. Save behavior:
- Save writes canonical JSON to original path.
- Unknown top-level fields remain preserved.
- External file drift shows warning but save still succeeds and overwrites.

6. History/session:
- Multiple runs remain as separate tabs.
- Restarting UI process clears history (no persistence).

## Assumptions and Defaults
1. Linux-only behavior remains unchanged.
2. UI server binds to `127.0.0.1` only.
3. Existing `--monitor` plain log-file workflow is intentionally removed (confirmed).
4. Working directory for runs is always the startup directory.
5. Command comes from startup args with UI override allowed.
6. No authentication is added in v1 due localhost-only binding.
