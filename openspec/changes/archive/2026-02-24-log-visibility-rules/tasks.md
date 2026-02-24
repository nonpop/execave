## 1. FS Log Rules

- [x] 1.1 Add `LogRule` type, `ParseLogRule`, and `ValidateLogRules` to `internal/fsrules/` with integration tests covering all spec scenarios (syntax validation, tilde expansion, relative paths, duplicate detection)
- [x] 1.2 Add `LogResolver` with `Visible(path string) bool` to `internal/fsrules/` with integration tests covering all resolution spec scenarios (longest prefix match, nolog, log override, default visible)

## 2. Net Log Rules

- [x] 2.1 Add `LogRule` type, `ParseLogRule`, and `ValidateLogRules` to `internal/netrules/` with integration tests covering all spec scenarios (syntax validation, target patterns, port patterns, duplicate identity, mixed port patterns)
- [x] 2.2 Add `LogResolver` with `Visible(host string, port uint16) bool` to `internal/netrules/` with integration tests covering all resolution spec scenarios (specificity ranking, nolog, log override, wildcard, CIDR, default visible)

## 3. Config Integration

- [x] 3.1 Extend `Config` struct with `FSLogRules` and `NetLogRules` fields. Update `parseRules` to route `fs:log`/`fs:nolog` to `fsrules.ParseLogRule` and `net:log`/`net:nolog` to `netrules.ParseLogRule`. Update `ParseRules` to call `fsrules.ValidateLogRules` and `netrules.ValidateLogRules`. Update integration tests for all modified config spec scenarios.

## 4. Web UI Frontend Filtering

- [x] 4.1 Update `Server` to accept FS and net log resolvers. Apply nolog resolution when rendering entries in `handleIndex` and `sendEntryEvent` (add `nolog` boolean field to SSE entry JSON).
- [x] 4.2 Add "Denied only" and "Apply nolog rules" checkboxes to the HTML template. Add client-side JS to toggle entry visibility by result type and nolog metadata without page reload.
- [x] 4.3 Update web-ui integration tests for all new and modified spec scenarios (default hidden OK entries, nolog filtering, filter toggles, SSE nolog metadata, independent filter axes).

## 5. E2E Tests

- [x] 5.1 Update E2E tests in `test/e2e/monitoring_access_test.go` for new and modified `monitoring-access` playbook use cases (denied-only default, show all toggle, fs:nolog, fs:log override, net:nolog, net:log override, nolog toggle, independent filters, specificity)

## 6. Documentation

- [x] 6.1 Update `docs/architecture.md` and `docs/security-model.md` to describe log visibility rules (display-only, no security impact)
- [x] 6.2 Update `openspec/config.yaml` context section to mention log visibility rules
