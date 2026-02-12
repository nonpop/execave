## 1. Thread-safe Logger

- [x] 1.1 Add concurrent access test to `internal/accesslog/accesslog_test.go`: multiple goroutines calling `Log()` simultaneously with distinct entries, assert no entries lost and no races (run with `-race`)
- [x] 1.2 Add `sync.Mutex` to `Logger` struct, wrap `Log()` body with `Lock()`/`Unlock()`
- [x] 1.3 Verify existing accesslog tests pass

## 2. Unbuffered log writer

- [x] 2.1 Change `createAccessLogWriter` in `cmd/execave/main.go` to return `*os.File` directly instead of `*bufio.Writer`; update cleanup to just close the file (no flush)
- [x] 2.2 Update `setupAccessLog` and `newMonitorTestEnv` if needed to match new writer type
- [x] 2.3 Verify existing monitor and E2E tests pass

## 3. Pipe-based strace output

- [x] 3.1 Add unit test for `Monitor.Run` verifying log entries are written before `Run` returns (existing tests already cover this implicitly, but confirm they pass with the pipe change)
- [x] 3.2 Replace `createStraceOutputFile` with pipe creation: `os.Pipe()` returning `(pr, pw)`
- [x] 3.3 Update `buildStraceArgs` to use `-o /proc/self/fd/3` instead of `-o <tmpPath>`; accept pipe write end for `ExtraFiles`
- [x] 3.4 Restructure `Run`: start strace with pw as `ExtraFiles[0]` → close pw in parent → goroutine reads pr via `processStraceOutput` → `cmd.Wait()` → wait for goroutine → return exit code and processing error
- [x] 3.5 Remove `createStraceOutputFile` and `processStraceResults` (no longer needed)
- [x] 3.6 Verify all existing monitor unit tests and E2E tests pass

## 4. E2E tests for new spec scenarios

- [x] 4.1 Scenario "Log entries visible during execution": start monitored sandbox with a command that reads a file then sleeps; while sandbox is still running, read the log file and assert the READ entry is present before the command exits
- [x] 4.2 Scenario "Log entries appear in syscall order": sandboxed process reads `a.txt` then writes `b.txt` in sequence; assert the READ entry appears before the WRITE entry in the log
- [x] 4.3 Scenario "Concurrent filesystem and network entries": config with both fs and net rules; sandboxed process reads a file and makes an HTTPS request; assert both entries present in log without loss or corruption

## 5. Documentation and comments

- [x] 5.1 Update SIGINT comment in `cmd/execave/main.go` to reflect pipe draining instead of post-processing
- [x] 5.2 Update `accesslog.Logger` godoc to note thread safety
- [x] 5.3 Update `docs/architecture.md` if it describes the temp-file-based monitoring flow
