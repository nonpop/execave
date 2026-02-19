## 1. Implementation

- [x] 1.1 Add exported `ParseRules` function to `internal/config/config.go` — takes `(rawRules []string, configDir, configPath string, managedPaths []string)`, calls `parseRules` → `fsrules.Validate` → `netrules.Validate` → assembles `*Config`.
- [x] 1.2 Refactor `Load` to call `ParseRules` after file read and TOML unmarshal. Verify all existing tests still pass.

## 2. Tests

- [x] 2.1 Unit tests for `ParseRules` in `internal/config/config_test.go` (white-box): valid fs+net rules, tilde expansion, relative path resolution, invalid rule, duplicate paths, managed path rejection, config writability rejection, empty rules.
- [x] 2.2 Integration test in `internal/config/integration_test.go` (black-box): `Load` and `ParseRules` produce identical Config for the same rule strings.
- [x] 2.3 Run existing fuzz test (`config_fuzz_test.go`) for 30 seconds to verify no regressions.

## 3. Docs

- [x] 3.1 Add godoc comment to `ParseRules` explaining parameters (especially that `configPath` is for validation, not I/O) and relationship to `Load`.
