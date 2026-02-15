## 1. Runner package

- [x] 1.1 Create `internal/runner/` package with `Runner` struct, `RunStatus` type, and `New` constructor
- [x] 1.2 Implement `Start` — create fresh logger, build sandbox+monitor, run in goroutine, update status
- [x] 1.3 Implement `Stop` — cancel context, wait for goroutine, no-op when idle
- [x] 1.4 Implement start-stops-active — `Start` calls `Stop` before starting a new run
- [x] 1.5 Implement `Status`, `Logger`, `Subscribe`, `Unsubscribe`
- [x] 1.6 Integration tests for runner spec scenarios (`internal/runner/integration_test.go`)

## 2. WebUI changes

- [x] 2.1 Move `RunStatus` from `webui` to `runner`. Remove `StatusProvider` interface. Delete `cmd/execave/status.go`
- [x] 2.2 Change `webui.Server` to take `*runner.Runner` instead of `StatusProvider` + `*accesslog.Logger`
- [x] 2.3 Add `POST /api/start` and `POST /api/stop` handlers
- [x] 2.4 Add Start/Restart and Stop buttons to `index.html` — Start when idle, Restart when running, Stop always visible but disabled when idle
- [x] 2.5 JS: button click handlers call `/api/start` and `/api/stop`, status SSE events update button labels and disabled state
- [x] 2.6 Update SSE handler to re-read logger from runner on status change to "running" (new session event clears browser table)
- [x] 2.7 Update existing webui integration tests — replace `MockStatus` with `*runner.Runner` or test helpers
- [x] 2.8 Integration tests for new web-ui spec scenarios (run control endpoints, button rendering)

## 3. CLI refactor

- [x] 3.1 Refactor `runMonitored` in `cmd/execave/main.go` to create runner, pass to webui, call `runner.Start` for initial run

## 4. E2E tests

- [x] 4.1 E2E tests for `iterating-config` playbook use cases in `test/e2e/iterating_config_test.go`: test start/stop/restart via HTTP API (POST endpoints + SSE status events)
- [x] 4.2 Skipped placeholder tests for JS-driven interactions (button clicks, SSE DOM updates) with `t.Skip("needs browser/JS execution")` — same pattern as `TestE2E_MonitoringAccess_NoEntriesLostOnPageRefresh`

## 5. Docs

- [x] 5.1 Update `docs/architecture.md` for new `internal/runner` package
- [x] 5.2 Update `openspec/config.yaml` context section to mention runner
