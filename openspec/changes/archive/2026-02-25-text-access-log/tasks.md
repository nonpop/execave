## 1. Extract shared logic to `internal/logfilter`

- [x] 1.1 Create `internal/logfilter/shorten.go` with exported `ShortenPath` — move from `internal/webui/shorten.go`, export, add godoc. Move unit tests from `internal/webui/server_test.go` (`TestShortenPath_*`) to `internal/logfilter/shorten_test.go`.
- [x] 1.2 Create `internal/logfilter/nolog.go` with `IsNolog(entry accesslog.Entry, fsRes *fsrules.LogResolver, netRes *netrules.LogResolver) bool` — extract pure logic from `webui.Server.isNolog()`. Write unit tests in `internal/logfilter/nolog_test.go` (FS/net entry types, nil resolvers, malformed HTTP target, panic on unexpected operation).

## 2. Refactor `webui` to use `logfilter`

- [x] 2.1 Replace `webui.shortenPath` calls with `logfilter.ShortenPath`. Delete `internal/webui/shorten.go`. Update `isNolog()` method to delegate to `logfilter.IsNolog`. Verify all existing webui tests pass.
- [x] 2.2 Add `FilterDefaults` struct (ShowAllowed, ShowNolog bools) to `webui` package. Add field to `Server`, accept in `New()`. Pass to template data as `DeniedOnlyChecked` / `ApplyNologChecked`. Update `templates/index.html` checkbox attributes: `{{if .DeniedOnlyChecked}}checked{{end}}`. Update test helpers (`StartServer`, `StartServerWithPaths`, `StartServerWithRunner`) and direct `webui.New()` calls in integration tests.
- [x] 2.3 Write integration tests for filter defaults: default state keeps checkboxes checked, ShowAllowed=true unchecks "Denied only", ShowNolog=true unchecks "Apply nolog rules".

## 3. Create `internal/textlog` package

- [x] 3.1 Create `internal/textlog/writer.go` with `Writer` type: `New()` constructor, `Run(ctx, logger)` method (subscribe loop with final drain), internal `formatEntry()`. Format: `%-7s %-5s  %s  (%s)\n`. Uses `logfilter.ShortenPath` for FS paths, `logfilter.IsNolog` for nolog filtering. Write unit tests for `formatEntry` in `internal/textlog/writer_test.go`.
- [x] 3.2 Write integration tests in `internal/textlog/integration_test.go`: OK entries hidden by default, OK entries shown with showAllowed, nolog entries hidden by default, nolog entries shown with showNolog, independent filter axes, path shortening applied, final drain on context cancellation.

## 4. CLI flag changes and `runMonitored` refactor

- [x] 4.1 Change `--monitor` from `BoolVar` to `StringVar` with `NoOptDefVal = "web"`. Add `--show-allowed` and `--show-nolog` `BoolVar` flags. Thread through `runCommand` → `runSandboxed` → `runMonitored`. Replace `monitor bool` checks with `monitor != ""`.
- [x] 4.2 Split `runMonitored()`: shared setup (runner, proxy wiring, log resolvers), then dispatch to `runMonitoredWeb()` (existing web UI flow, pass FilterDefaults) or `runMonitoredText()` (open file or buffer, create textlog.Writer, run, flush buffer to stderr if `-` mode).

## 5. E2E tests

- [x] 5.1 Write E2E tests in `test/e2e/`: text log to file contains deny entries, text log to stderr contains entries after exit, `--show-allowed` includes OK entries, `--show-nolog` includes nolog entries, bare `--monitor` still starts web UI (backward compat), filter flags set web UI checkbox initial state.

## 6. Documentation

- [x] 6.1 Update `README.md` with new `--monitor` flag syntax and filter flags. Update `docs/architecture.md` if it references `--monitor`. Update `openspec/config.yaml` context section.
