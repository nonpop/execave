## 1. Tunnel: Host-Side Bridge

- [x] 1.1 Add `StartBridge(udsPath string) (int, func(), error)` to `internal/tunnel/tunnel.go`: start TCP listener on `127.0.0.1:0`, launch `acceptLoop` goroutine, return port and a stop func that closes the listener and drains in-flight relays
- [x] 1.2 Add integration tests for `StartBridge`: bridge forwards TCP → UDS; stop func closes cleanly

## 2. Monitor: Extra Environment Injection

- [x] 2.1 Add `extraEnv []string` field to `monitor.Monitor`; add as parameter to `New()`; update callers to pass `nil`
- [x] 2.2 In `monitor.Run()`, when `extraEnv` is non-nil set `cmd.Env = append(os.Environ(), extraEnv...)`
- [x] 2.3 Add integration tests for `extraEnv`: verify injected vars appear in traced command's environment; verify nil extraEnv inherits parent env

## 3. Runner: Unsandboxed Mode

- [x] 3.1 Add `noSandbox bool` field to `runner.Runner`; update `New()` to accept it
- [x] 3.2 In `runner.Start()`: when `noSandbox=true`, skip `sandbox.ResolveBwrap`, `sandbox.New`/`BuildBwrapArgs`, and `seccomp.FilterPipe`; if `netPath` non-nil, call `tunnel.StartBridge(netPath.UDSPath)` and build HTTP_PROXY extraEnv; pass empty bwrap args, nil seccomp, and extraEnv to `monitor.New()`; call `stop()` after `monitor.Run()` returns
- [x] 3.3 Add integration tests for noSandbox mode: command runs without bwrap; access log entries produced; HTTP_PROXY injected when netPath configured; seccomp not applied

## 4. CLI: `--no-sandbox` Flag

- [x] 4.1 Add `--no-sandbox` bool flag to `cmd/execave/main.go`
- [x] 4.2 Validate that `--monitor` is also set when `--no-sandbox` is used; exit with usage error if not
- [x] 4.3 Pass `noSandbox` to `runMonitored`; pass to `runner.New()` in `runMonitored`

## 5. Docs and Spec Updates

- [x] 5.1 Update `openspec/config.yaml` context section to mention `--no-sandbox` (requires `--monitor`; no bwrap/seccomp; proxy starts, HTTP_PROXY injected via host bridge)

## 7. UNENFORCED Result

- [x] 7.1 Add `ResultUnenforced ResultType = "UNENFORCED"` to `internal/accesslog/accesslog.go`
- [x] 7.2 Add `unenforced bool` parameter to `accesslog.New()`; when `unenforced=true`, the logger SHALL override the Result of every entry to `ResultUnenforced` before storing
- [x] 7.3 Update `internal/accesslog/accesslog.go` callers of `New()` to pass `unenforced=false`
- [x] 7.4 In `runner.Start()` no-sandbox path, pass `unenforced=true` when constructing the `accesslog.Logger`
- [x] 7.5 Update `internal/textlog/writer.go`: change RESULT padding from `%-7s` to `%-10s`; treat `UNENFORCED` like `DENY`/`UNKNOWN` (always shown, not filtered by `showAllowed`)
- [x] 7.6 Add access-log integration tests for unenforced mode: result override works; normal mode preserves result
- [x] 7.7 Add text-log integration tests for UNENFORCED: entry formatted correctly; shown when showAllowed=false
- [x] 7.8 Update E2E test 6.1: assert entries have result `UNENFORCED` (not `DENY`)

