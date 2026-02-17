## 1. TOML Config Format

- [x] 1.1 Add `github.com/BurntSushi/toml` dependency (`go get`)
- [x] 1.2 [SECURITY] Read `docs/security-model.md` — confirm TOML parsing sits at the same trust boundary as JSON parsing and no new attack surface is introduced
- [x] 1.3 Write failing integration tests for new `config` spec scenarios: TOML valid config, comments, trailing comma (update existing JSON scenarios to TOML format)
- [x] 1.4 Replace `encoding/json` with `BurntSushi/toml` in `config.Load`; update default config path constant in `cmd/execave/main.go` to `execave.toml`
- [x] 1.5 Update all test helpers (unit, integration, E2E) to write `.toml` configs instead of `.json` — update `writeConfig`/`writeConfigInDir` in `test/e2e/helpers_test.go` and any inline config strings in other tests
- [x] 1.6 Run config fuzz target for at least 30 seconds to check for regressions: `go test -fuzz=FuzzLoad ./internal/config/ -fuzztime=30s`
- [x] 1.7 Update E2E tests for modified use cases in `configuring-execave` playbook: default config filename (`execave.toml`), comments in config, config-not-found error message
- [x] 1.8 Update `openspec/config.yaml` context to reflect TOML format

## 2. Tilde Expansion in FS Rules

- [x] 2.1 [SECURITY] Confirm tilde expansion produces an absolute path that passes through existing managed-path, duplicate, and config-writability validation unchanged
- [x] 2.2 Write failing unit tests for new `fs-rules` spec scenarios: `~/project`, bare `~`, `~/project/../other`, `~otheruser/data`
- [x] 2.3 Implement tilde expansion in `fsrules.normalizePath`: expand `~/` prefix and bare `~` to `os.UserHomeDir()`; return error if `os.UserHomeDir()` fails
- [x] 2.4 Run fsrules fuzz targets for at least 30 seconds: `go test -fuzz=FuzzParse ./internal/fsrules/ -fuzztime=30s` and `go test -fuzz=FuzzResolver ./internal/fsrules/ -fuzztime=30s`
- [x] 2.5 Add E2E tests for tilde expansion use cases: tilde in rule mounts correctly, tilde in validation error shows expanded path

## 3. Path Shortening in Web UI

- [x] 3.1 Implement `shortenPath(absPath, homeDir, configDir string) string` in `internal/webui` (unexported); cover all spec scenarios with unit tests
- [x] 3.2 Update `webui.Server` to accept `homeDir` and `configDir` (pass from `main` via constructor or `New` parameters)
- [x] 3.3 Write failing integration tests for new and modified `web-ui` spec scenarios: relative-form shortening, tilde-form shortening, non-filesystem targets unchanged, SSE entry event shortened path
- [x] 3.4 Apply `shortenPath` to `Entry.Target` in `handleIndex` (HTML template rendering) and `sendEntryEvent` (SSE JSON marshaling) — only for filesystem entries (operation READ or WRITE); network entries (`HTTPS`, `HTTP`) pass through unchanged
- [x] 3.5 Update E2E tests for modified monitoring use cases: target column shows shortened paths, rule column shows verbatim rule strings

## 4. Documentation

- [x] 4.1 Update `README.md`: config format section (JSON → TOML, example config, tilde paths)
- [x] 4.2 Update `docs/architecture.md`: config parsing section
- [x] 4.3 Update `docs/security-model.md` if any security invariant descriptions reference JSON or absolute-only paths
