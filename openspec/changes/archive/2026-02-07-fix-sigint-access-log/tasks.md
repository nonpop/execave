## 1. E2E Test (TDD: failing test first)

- [x] 1.1 Add E2E test `TestE2E_Monitor_AccessLogWrittenAfterChildTerminatedBySIGINT` in `test/e2e/monitor_test.go`. The test should: run execave with `--monitor` wrapping a long-running command (e.g., `sleep 60`), send SIGINT to the execave process after a short delay, then assert that the access log file exists and contains entries, and that the exit code is 130. Use `cmd.Process.Signal(syscall.SIGINT)` to send the signal to the process (not the process group, since the test helper captures stdout/stderr via pipes and the child is not in the terminal's foreground process group — so the signal must be sent explicitly). Note: signal must be sent to the process group (using negative PID with `syscall.Kill`) so that strace/bwrap also receive it, mimicking real ctrl-c behavior.

## 2. Implementation

- [x] 2.1 In `cmd/execave/main.go`, add `signal.Ignore(syscall.SIGINT)` in `runCommand()` before the monitor/sandbox execution paths. Import `os/signal` and `syscall`.

## 3. Verify

- [x] 3.1 Run the new E2E test and confirm it passes.
- [x] 3.2 Run the full test suite (`go test ./...`) and confirm no regressions.
