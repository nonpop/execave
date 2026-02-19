## Why

`config.Load` couples file I/O with rule parsing and validation. The planned web UI config editor needs to parse and validate rules from in-memory strings (user draft edits), not just from files on disk. Extracting the non-I/O logic into an exported function unblocks this.

## What Changes

- Add exported `config.ParseRules(rawRules, configDir, configPath, managedPaths)` that parses raw rule strings and validates them, returning a `*Config` or error.
- Refactor `config.Load` to delegate to `ParseRules` after file read and TOML unmarshal. No behavior change.

## Playbooks

### New Playbooks

(none)

### Modified Playbooks

(none — this is a pure internal refactor; no user-facing behavior changes)

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `config`: Add requirement for `ParseRules` — parsing rules from in-memory strings with the same validation guarantees as `Load`.

## Impact

- **Code**: `internal/config/config.go` — new exported function, `Load` refactored to use it.
- **Tests**: New unit and integration tests for `ParseRules`.
- **Security**: No change to trust boundaries. `ParseRules` applies the same validation (duplicate detection, managed path rejection, config writability check) as `Load`. The config parsing trust boundary (user-provided rule strings) is unchanged — the same validation runs regardless of whether strings come from a file or from memory.
- **Config format**: No changes. TOML format and rule syntax are unchanged.
