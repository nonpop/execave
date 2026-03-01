## 1. Core Implementation

- [x] 1.1 Update `ParseTOML` in `internal/config/config.go` to unmarshal top-level `fs`, `net`, `syscall` array keys; reconstruct prefixed rule strings (`fs:...`, `net:...`, `syscall:...`); delegate to `ParseRules`
- [x] 1.2 Update godoc on `ParseTOML` and `Load` to describe the new `fs`/`net`/`syscall` flat key format

## 2. Unit & Integration Tests

- [x] 2.1 Update all TOML literal strings in `internal/config/config_test.go` to use the new section format
- [x] 2.2 Update all TOML literal strings in `internal/config/integration_test.go` to use the new section format; remove/replace the `TestIntegration_ConfigFileFormat_UnknownResourceType` scenario (no longer applicable via `Load`)
- [x] 2.3 Update fuzz seed corpus strings in `internal/config/config_fuzz_test.go`

## 3. E2E Tests

- [x] 3.1 Rewrite `tomlConfig()` helper in `test/e2e/helpers_test.go` to emit the new flat key format (`fs = [...]`, `net = [...]`, `syscall = [...]`; grouped by prefix, prefix stripped)
- [x] 3.2 Update hardcoded TOML strings in `test/e2e/configuring_execave_test.go` (config-file-writable test, comments test)
- [x] 3.3 Update `TestE2E_ConfiguringExecave_UnknownResourceTypeRejected` — adjust expected error or replace with a test for invalid action within a section
- [x] 3.4 Update `TestE2E_IteratingConfig_InvalidConfigRejectedOnStart` — adjust expected error to match the new format

## 4. Docs & Example

- [x] 4.1 Update `execave.toml.example` to use the new `fs`/`net`/`syscall` flat key format
- [x] 4.2 Update `README.md` rule format descriptions and example snippet
- [x] 4.3 Update `docs/architecture.md` Config section description
- [x] 4.4 Update `openspec/config.yaml` context entry for config format

## 5. Verification

- [x] 5.1 Run `go test ./...` — all tests pass
- [x] 5.2 Run `golangci-lint run` — no new lint errors
- [x] 5.3 Run fuzz target for ≥30 seconds: `go test ./internal/config/... -fuzz FuzzLoad -fuzztime 30s`
