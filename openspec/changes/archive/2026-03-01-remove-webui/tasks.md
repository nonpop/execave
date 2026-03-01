## 1. Core CLI changes

- [x] 1.1 Remove `webui` import from `cmd/execave/main.go`
- [x] 1.2 Remove `noOpen` variable and `--no-open` flag definition
- [x] 1.3 Change `--monitor` `NoOptDefVal` from `"web"` to `"-"`
- [x] 1.4 Update `--monitor` help text: "Enable access monitoring. Without a value writes text log to stderr after process exits. With a path writes text log to that file in real-time."
- [x] 1.5 Update `--show-allowed` help text: remove web UI reference
- [x] 1.6 Update `--show-nolog` help text: remove web UI reference
- [x] 1.7 Remove `noOpen` parameter from `runCommand` → `runSandboxed` → `runMonitored` call chain
- [x] 1.8 Remove `sigCh` parameter from `runMonitored` signature and call site
- [x] 1.9 Delete `runMonitoredWeb` function and `monitorMode == "web"` branch in `runMonitored`
- [x] 1.10 Update SIGINT comment (line 155-158): remove web UI purpose, keep cleanup purpose
- [x] 1.11 Update `logContext` godoc: remove "web UI" reference

## 2. Delete web UI package

- [x] 2.1 Delete `internal/webui/` directory (server.go, server_test.go, integration_test.go, templates/)

## 3. Delete web-UI-only E2E tests

- [x] 3.1 Delete `test/e2e/iterating_config_test.go` (all 7 tests are webui-only)

## 4. E2E test helper refactoring

- [x] 4.1 Add `thenStderrHasEntry(substrings...)` to scenario in `test/e2e/helpers_test.go`
- [x] 4.2 Remove `monitoredResult` struct, `monitorRunOpts` struct
- [x] 4.3 Remove `runMonitoredCmd`, `runExecaveMonitored`, `fetchWebUI`, `monitorEndpoint`, `assertWebUIHasEntry`, `parseTableRows`, `sseEvent`, `readSSEEvents`, `startMonitoredExecave` functions
- [x] 4.4 Remove `scenario.lastWebUI`, `scenario.monitorURL` fields
- [x] 4.5 Remove `whenRunMonitored`, `whenRunMonitoredWithInterrupt`, `whenRunMonitoredWithFlags` methods
- [x] 4.6 Remove `thenWebUIHasEntry`, `thenWebUIContains`, `thenWebUINotContains`, `thenWebUICountOf` methods
- [x] 4.7 Clean up `s.lastWebUI = ""` / `s.monitorURL = ""` from remaining `when*` methods
- [x] 4.8 Clean up unused imports from `helpers_test.go`

## 5. Convert E2E tests in `monitoring_access_test.go`

- [x] 5.1 Delete web-UI-only tests: `WebUISurvivesSandboxExit`, `SIGINTAfterSandboxExitStopsWebUI`, `RunStatusShownInWebUI`, `RealTimeStreamingViaWebUI`
- [x] 5.2 Convert `ViewAccessLogInWebUI` → text log with `--show-allowed`, rename to `ViewAccessLogInTextOutput`
- [x] 5.3 Convert `MonitorNetworkAccess` → text log with `--show-allowed`
- [x] 5.4 Convert `MonitorBothFilesystemAndNetworkConcurrently` → text log with `--show-allowed`
- [x] 5.5 Convert `MonitorWithoutNetRules` → text log (DENY only, no extra flags)
- [x] 5.6 Convert `AccessLogAfterSIGINT` → text log to file with custom SIGINT handling
- [x] 5.7 Convert `LogDeduplication` → text log with `--show-allowed`, count stderr lines
- [x] 5.8 Convert `SymlinkResolutionHopsLogged` → text log with `--show-allowed`
- [x] 5.9 Convert `VerifyFilesystemEnforcement` → text log with `--show-allowed`
- [x] 5.10 Convert `VerifyNetworkEnforcement` → text log with `--show-allowed`
- [x] 5.11 Convert `MonitorReflectsFilesystemRulePrecedence` → text log with `--show-allowed`
- [x] 5.12 Convert `MonitorReflectsNetworkRulePrecedence` → text log with `--show-allowed`
- [x] 5.13 Convert `BarePathRelativeAccesses` → text log with `--show-allowed`
- [x] 5.14 Convert `UnresolvedRelativePath` → text log (UNKNOWN, no extra flags)
- [x] 5.15 Convert `DeniedOnlyDefaultView` → verify OK entries absent from stderr by default
- [x] 5.16 Convert `NologRuleSuppressesEntries` → text log nolog filtering assertions
- [x] 5.17 Convert `LogOverridesNolog` → text log log-override assertions

## 6. Convert E2E tests in `preventing_sandbox_escape_test.go`

- [x] 6.1 Convert `SymlinkChainBrokenAtDeniedIntermediateHop` → `whenRunTextLogWithFlags` + `thenStderrHasEntry`
- [x] 6.2 Convert `SymlinkLoopHitsDepthLimit` → `whenRunTextLog` + `thenStderrHasEntry`

## 7. Convert E2E tests in `text_log_test.go`

- [x] 7.1 Delete `BareMonitorStartsWebUI`, `ShowAllowedSetsWebUICheckboxState`, `ShowNologSetsWebUICheckboxState`
- [x] 7.2 Add `BareMonitorWritesToStderr` test: verify bare `--monitor` writes denied entries to stderr

## 8. Build and test

- [x] 8.1 Verify `CGO_ENABLED=0 go build -o ./bin/execave ./cmd/execave` succeeds
- [x] 8.2 Verify `go test ./...` passes
- [x] 8.3 Verify `golangci-lint run --fix` passes

## 9. Update documentation

- [x] 9.1 Update `docs/architecture.md`: remove WebUI and Browser from mermaid diagram, delete Web UI section, update LogFilter/AccessLog/Runner descriptions, update Data Flow section
- [x] 9.2 Update `docs/security-model.md`: "web UI" → "text log output", "toggle off in web UI" → "use --show-nolog"
- [x] 9.3 Update `docs/testing.md`: remove `whenRunMonitored*` and `thenWebUI*` entries, add `thenStderrHasEntry`
- [x] 9.4 Update `README.md`: rewrite monitoring section, remove web UI mode, `--no-open`, config editor, checkbox references
- [x] 9.5 Delete `docs/scratchpad/web-monitor-ui-plan.md`
- [x] 9.6 Update `docs/scratchpad/todo.md`: remove "simplify webui" item

## 10. Update OpenSpec artifacts

- [x] 10.1 Update `openspec/config.yaml`: remove "webui" from arch list, update monitoring description, delete Web UI subsection, update filter flag description
- [x] 10.2 Update `openspec/specs/runner/spec.md`: remove "from the web UI" from purpose
- [x] 10.3 Update incidental code comments: `internal/logfilter/shorten.go`, `internal/runner/runner.go`, `internal/runner/integration_test.go`, `internal/config/config.go`

## 11. Update active OpenSpec changes

- [x] 11.1 Update `openspec/changes/add-seccomp-filtering/`: remove web UI checkbox goal, decision, tasks, playbook use case
- [x] 11.2 Update `openspec/changes/log-seccomp-denials/`: "web UI" → "text log" in design and playbook
