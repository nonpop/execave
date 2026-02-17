## Why

The config file is plain JSON with no comment support, paths must be written as full absolute paths, and the access log displays raw absolute paths. These friction points make configs harder to read, share, and annotate, and make the access log harder to scan.

## What Changes

- **BREAKING**: Config format changes from JSON to TOML (`.toml` extension, `BurntSushi/toml` library). The flat `rules = [...]` model is preserved — same rule strings, new container format with native comment support.
- Tilde (`~`) expansion in filesystem rule paths: `fs:rw:~/project` expands to the user's home directory at parse time.
- Access log path shortening in the web UI: absolute paths are shortened to relative (relative to config directory) or `~/...` form, whichever is shorter. Rules in the log are shown verbatim from the config.

**Security impact**: Tilde expansion is deterministic (`os.UserHomeDir()`) and happens at config parse time before any sandbox creation — no change to sandbox boundaries or rule resolution. TOML parsing replaces JSON parsing in the config trust boundary; the rule string format (`fs:rw:/path`, `net:https:host:port`) is unchanged. Path shortening is display-only in the webui — stored data remains canonical absolute paths.

## Playbooks

### New Playbooks

None.

### Modified Playbooks

- `configuring-execave`: Config file format changes from JSON to TOML. Default config name changes from `execave.json` to `execave.toml`. Tilde paths are now valid in rules.
- `monitoring-access`: Web UI displays shortened paths in the access log target column.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `config`: Config file format changes from JSON to TOML.
- `fs-rules`: `Parse` accepts `~/...` paths and expands tilde to home directory.
- `web-ui`: Access log entries display shortened target paths (path shortening is an internal display utility within the webui package).

## Impact

- **Config parsing** (`internal/config`): Replace `encoding/json` with `BurntSushi/toml`. New dependency.
- **FS rules** (`internal/fsrules`): `normalizePath` gains tilde expansion.
- **Web UI** (`internal/webui`): Rendering applies path shortening to entry targets.
- **Tests**: All config-related test helpers switch from JSON to TOML. E2E tests update config file generation.
- **Documentation**: `README.md`, `docs/architecture.md`, `docs/security-model.md` references to JSON config format.
- **OpenSpec context**: Update `openspec/config.yaml` context to reflect TOML format.
