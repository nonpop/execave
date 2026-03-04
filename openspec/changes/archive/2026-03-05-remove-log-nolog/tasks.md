## 1. Remove CLI --show-nolog flag

- [x] 1.1 Write failing integration test: `execave monitor --show-nolog` exits with "unknown flag" error
- [x] 1.2 Remove `--show-nolog` flag definition from `cmd/execave/commands/monitor.go`
- [x] 1.3 Remove `showNolog` field from monitor options struct and all usages in that file

## 2. Remove textlog showNolog filter

- [x] 2.1 Write failing unit test: `textlog.Writer` no longer accepts a `showNolog` parameter (or has no nolog filtering)
- [x] 2.2 Remove `showNolog` parameter from `Writer` constructor in `internal/textlog`
- [x] 2.3 Remove nolog filter branch from `Writer.run` / entry filtering logic
- [x] 2.4 Update all callers of `textlog.NewWriter` (in `internal/run/run.go` or similar) to drop the `showNolog` argument

## 3. Remove logfilter IsNolog

- [x] 3.1 Write failing unit test: `logfilter.IsNolog` no longer exists (call fails to compile)
- [x] 3.2 Remove `IsNolog` function from `internal/logfilter`
- [x] 3.3 Remove any calls to `IsNolog` across the codebase (check textlog, accesslog)

## 4. Remove accesslog nolog support

- [x] 4.1 Remove nolog-related methods or fields from `internal/accesslog` (identified in `nolog_test.go`)
- [x] 4.2 Delete or update `internal/accesslog/nolog_test.go`

## 5. Remove Config log rule fields and parsing

- [x] 5.1 Write failing integration test: config with `fs = ["nolog:/usr"]` returns an error on load
- [x] 5.2 Write failing integration test: config with `net = ["nolog:*.example.com:*"]` returns an error
- [x] 5.3 Write failing integration test: config with `syscall = ["nolog:ptrace"]` returns an error
- [x] 5.4 Remove `FSLogRules`, `NetLogRules`, and syscall nolog fields from `Config` struct in `internal/config/config.go`
- [x] 5.5 Remove `parseFSLogRule`, `parseNetLogRule`, `parseSyscallRule` nolog branches and `actionNolog` constant from `internal/config/config.go`
- [x] 5.6 Remove log rule validation calls (`validateLogRules` etc.) from `config.go`
- [x] 5.7 Remove log rule scenarios from `internal/config/integration_test.go` and add rejection scenarios
- [x] 5.8 Update `internal/config/config_fuzz_test.go` to remove log rule generation

## 6. Remove fsrules log rules

- [x] 6.1 Remove log rule scenarios from `internal/fsrules/integration_test.go`
- [x] 6.2 Delete `internal/fsrules/logrules.go`
- [x] 6.3 Delete any fsrules-specific logrules unit test files

## 7. Remove netrules log rules

- [x] 7.1 Remove log rule scenarios from `internal/netrules/integration_test.go`
- [x] 7.2 Delete `internal/netrules/logrules.go`
- [x] 7.3 Delete any netrules-specific logrules unit test files

## 8. Remove syscallrules log rules

- [x] 8.1 Delete `internal/syscallrules/logrules.go`
- [x] 8.2 Delete `internal/syscallrules/logrules_test.go`
- [x] 8.3 Delete `internal/syscallrules/logrules_fuzz_test.go`

## 9. Update E2E tests

- [x] 9.1 Remove E2E test cases for all REMOVED and MODIFIED use cases in `test/e2e/monitoring_access_test.go` (nolog suppression, toggle, specificity, filter independence use cases)
- [x] 9.2 Remove E2E test cases for nolog use cases from `test/e2e/text_log_test.go`
- [x] 9.3 Remove E2E test cases referencing `--show-nolog` from all E2E files
- [x] 9.4 Add E2E test: config file with `fs:nolog:` rule causes `execave` to exit with an error
- [x] 9.5 Update E2E test for "Write access log to file" use case to remove the nolog bullet point assertion

## 10. Verify and clean up

- [x] 10.1 Run `go build ./...` — no compile errors
- [x] 10.2 Run `go test ./...` — all tests pass
- [x] 10.3 Run `golangci-lint run --fix` — no lint errors
- [x] 10.4 Grep for any remaining `nolog`, `showNolog`, `IsNolog`, `LogRule`, `LogResolver` references in non-archive code and remove them
