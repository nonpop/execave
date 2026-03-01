## Why

The current flat `rules = [...]` array mixes `fs:`, `net:`, and `syscall:` rules, making configs hard to scan as they grow. Splitting into top-level typed array keys (`fs = [...]`, `net = [...]`, `syscall = [...]`) improves readability without changing semantics — the resource-type prefix becomes implicit from the key name.

## What Changes

- **BREAKING**: Config format changes from a flat `rules` array to top-level typed array keys:
  - `rules = ["fs:ro:/usr", "net:http:api.example.com:443"]` → `fs = ["ro:/usr"]\nnet = ["http:api.example.com:443"]`
- Rule strings within each key drop the resource-type prefix (`fs:`, `net:`, `syscall:`)
- `syscall` rules get their own explicit `syscall` key (previously mixed into the flat array)
- All three keys (`fs`, `net`, `syscall`) are optional — omitting a key means no rules of that type
- `ParseTOML` updated to unmarshal the three top-level keys; `ParseRules` unchanged (still accepts prefixed strings internally)
- `execave.toml.example` updated to demonstrate the new format
- README and architecture docs updated

## Playbooks

### New Playbooks
<!-- none -->

### Modified Playbooks
- `configuring-execave`: The config file format use cases show the new format; the "invalid rule syntax" use cases reference the new error messages

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `config`: The config file format requirement changes — top-level `fs`, `net`, `syscall` array keys replace the flat `rules` array; scenarios updated to reflect new TOML shape

## Impact

- `internal/config/config.go`: `ParseTOML` struct tag changes; `ParseRules` unaffected
- `internal/config/config_test.go`, `integration_test.go`, `config_fuzz_test.go`: All TOML literal strings updated
- `test/e2e/helpers_test.go`: `tomlConfig()` helper rewritten to emit the new format
- `test/e2e/configuring_execave_test.go`: Hardcoded TOML strings updated
- `execave.toml.example`, `README.md`, `docs/architecture.md`: Doc updates
- No changes to `fsrules`, `netrules`, `seccomp`, sandbox, proxy, or monitor — rule routing logic is internal to `ParseTOML` and untouched downstream
- Security impact: config parsing only; no changes to permission checks, rule resolution, sandbox boundaries, or bwrap invocation. The config is user-supplied input that is already fully validated by `ParseRules` before use — changing the surface format does not affect the validation pipeline or trust boundary.
