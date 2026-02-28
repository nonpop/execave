## Why

The web UI (`internal/webui/`) adds development overhead without sufficient benefit. Stderr and file-based text log monitoring, combined with manual config editing in an external editor, covers all practical workflows. Removing the web UI simplifies the codebase and reduces the maintenance surface.

## What Changes

- **BREAKING**: Remove the `internal/webui/` package entirely (server, templates, tests)
- **BREAKING**: Remove `--no-open` CLI flag (was web-UI-only)
- **BREAKING**: `--monitor` (bare, no value) changes from launching the web UI to writing text log to stderr after process exits (same as `--monitor=-`)
- Remove web UI spec (`openspec/specs/web-ui/`)
- Update `--show-allowed` and `--show-nolog` flag help text to remove web UI references
- Update all documentation, playbooks, and specs that reference the web UI

**Security impact**: None. The web UI was a display-only component on localhost with token auth. Its removal does not affect permission checks, rule resolution, sandbox boundaries, config parsing, or bwrap invocation. No trust boundaries change.

**Config format**: No changes. The TOML config format is unaffected.

## Playbooks

### New Playbooks

(none)

### Modified Playbooks

- `monitoring-access`: Remove web-UI-specific use cases (survives exit, SIGINT stops web UI, run status display, page refresh, filter checkbox state). Rewrite remaining use cases to reference text log instead of web UI.
- `iterating-config`: Rewrite entirely — currently describes the web UI edit/observe/restart loop. New version describes CLI-based workflow: edit config file → run with `--monitor` → observe text log → repeat.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `web-ui`: **Remove entirely** — delete spec
- `runner`: Update purpose description to remove web UI reference
- `text-log`: No requirement changes (text log behavior is unchanged)

## Impact

- **Code**: Delete `internal/webui/` (~2400 lines). Modify `cmd/execave/main.go` (remove import, function, flags). Update comments in `internal/logfilter/`, `internal/runner/`, `internal/config/`.
- **Tests**: Delete `test/e2e/iterating_config_test.go`. Convert ~20 E2E tests in `monitoring_access_test.go` and `preventing_sandbox_escape_test.go` from web UI assertions to text log assertions. Remove web UI helpers from `test/e2e/helpers_test.go`.
- **Documentation**: Update `docs/architecture.md`, `docs/security-model.md`, `docs/testing.md`, `README.md`, `openspec/config.yaml`. Delete `docs/scratchpad/web-monitor-ui-plan.md`.
- **OpenSpec changes**: Update `add-seccomp-filtering` and `log-seccomp-denials` change artifacts to remove web UI references.
- **Dependencies**: No external dependencies orphaned (web UI used only stdlib).
