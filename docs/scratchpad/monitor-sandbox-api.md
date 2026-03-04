# Cleaner Monitor-Sandbox API Surface

## Background

The monitor and sandbox packages are separate (different binaries, different kernel mechanisms) but the orchestrator `run.go` encodes too much knowledge of their internal contract when wiring them together. This document proposes a `Sandbox.PrepareForMonitoring()` method that encapsulates the wiring details.

### Context: how the two paths work today

**Non-monitored path** (`Sandbox.Run` in `internal/sandbox/sandbox.go`):
The sandbox resolves bwrap, builds bwrap args, creates a seccomp filter pipe at fd 3
(`ExtraFiles[0]`), inserts `--seccomp 3` into bwrap args, and runs bwrap directly.
Everything is self-contained.

**Monitored path** (`buildSandboxedMonitor` in `internal/run/run.go`):
The orchestrator does all the work that `Sandbox.Run` does internally, but differently:
1. Resolves bwrap binary and checks version (duplicating what `Sandbox.Run` does internally)
2. Calls `sb.BuildBwrapArgs(command)` to get raw bwrap args
3. Builds the syscall resolver from config, extracts allowed syscall names into a map
4. Creates a seccomp filter pipe via `seccomp.FilterPipe(allowedMap)`
5. Inserts `--seccomp 4` into bwrap args — fd 4 because in the monitored path, strace's output pipe occupies `ExtraFiles[0]` (fd 3), pushing seccomp to `ExtraFiles[1]` (fd 4)
6. Prepends bwrap path to make the full command
7. Checks `sb.HasNetworkPath()` to determine `setupExecves` (2 without tunnel, 3 with tunnel)
8. Passes `fullCommand`, `setupExecves`, and `seccompPipe` to `monitor.New()`

### What's wrong

- **fd numbering is an implicit contract.** `SeccompFilterFD = 4` in the sandbox package encodes knowledge that the monitor's strace pipe is fd 3. The orchestrator must use the right constant for the right path (3 in `Run`, 4 in monitored mode).
- **setupExecves computation leaks.** The orchestrator must query `HasNetworkPath()` and map it to 2 or 3. This is sandbox-internal knowledge (bwrap exec + optional tunnel exec).
- **Duplicate bwrap resolution.** Both `Sandbox.Run()` and `buildSandboxedMonitor()` resolve and version-check bwrap, but independently.
- **run.go does detailed sandbox assembly.** Steps 2-7 above are sandbox implementation details that the orchestrator shouldn't need to know.

## Proposed change

### New types and method in `internal/sandbox/`

```go
// MonitorInput holds the data a Monitor needs to trace a sandboxed command.
type MonitorInput struct {
    // FullCommand is the complete argv to pass to monitor.New: [bwrapPath] + bwrapArgs.
    FullCommand []string
    // SetupExecves is the number of execves the monitor should skip in strace output
    // before the user command starts (2 for bwrap, 3 for bwrap + network tunnel).
    SetupExecves int
    // SeccompPipe is the seccomp filter pipe to pass to monitor.New as extraFile.
    // The caller is responsible for not closing it before monitor.Run starts
    // (the monitor closes it after the child process inherits it).
    SeccompPipe *os.File
}

// PrepareForMonitoring builds the bwrap command and seccomp filter for use with
// a Monitor. It resolves the bwrap binary, builds bwrap args with the seccomp fd
// set for the monitored path (fd 4, after the strace pipe at fd 3), creates the
// seccomp filter pipe, and computes the setupExecves count.
//
// allowedSyscalls is the set of syscall names allowed by syscall:allow rules;
// nil means no allowed syscalls (all ruleable syscalls blocked by seccomp).
// The caller passes the result to monitor.New.
func (s *Sandbox) PrepareForMonitoring(command []string, allowedSyscalls map[string]bool) (*MonitorInput, error) {
    bwrapPath, err := binutil.ResolveBwrap()
    if err != nil {
        return nil, fmt.Errorf("prepare sandbox for monitoring: %w", err)
    }
    if warn, verr := binutil.CheckBwrapVersion(bwrapPath); verr != nil {
        return nil, fmt.Errorf("prepare sandbox for monitoring: %w", verr)
    } else if warn != "" {
        fmt.Fprintln(os.Stderr, "execave: warning:", warn)
    }

    bwrapArgs := s.BuildBwrapArgs(command)

    seccompPipe, err := seccomp.FilterPipe(allowedSyscalls)
    if err != nil {
        return nil, fmt.Errorf("prepare sandbox for monitoring: create seccomp filter: %w", err)
    }

    bwrapArgs = InsertSeccompArg(bwrapArgs, SeccompFilterFD)
    fullCommand := append([]string{bwrapPath}, bwrapArgs...)

    setupExecves := 2
    if s.HasNetworkPath() {
        setupExecves = 3
    }

    return &MonitorInput{
        FullCommand:  fullCommand,
        SetupExecves: setupExecves,
        SeccompPipe:  seccompPipe,
    }, nil
}
```

### Changes to `internal/run/run.go`

`buildSandboxedMonitor` becomes:

```go
func buildSandboxedMonitor(cfg *config.Config, absConfigPath, interpPath string, netPath *sandbox.NetworkPath, stracePath string, logger *accesslog.Logger, resolver *fsrules.Resolver, command []string) (*monitor.Monitor, error) {
    sb := sandbox.New(cfg, absConfigPath, netPath, interpPath)

    sr := buildSyscallResolver(cfg)
    allowedNames := sr.AllowedNames()
    allowedMap := make(map[string]bool, len(allowedNames))
    for _, name := range allowedNames {
        allowedMap[name] = true
    }

    input, err := sb.PrepareForMonitoring(command, allowedMap)
    if err != nil {
        return nil, fmt.Errorf("start monitored run: %w", err)
    }

    return monitor.New(stracePath, logger, resolver, input.FullCommand, input.SetupExecves, input.SeccompPipe, sr, false), nil
}
```

The bwrap resolution, bwrap arg building, seccomp fd insertion, full command assembly, and setupExecves computation are all gone from run.go. The syscall resolver construction stays in run.go because it's also used by `buildNoSandboxMonitor` and is a monitor concern (strace logging), not a sandbox concern.

### What to remove

- `sandbox.InsertSeccompArg` can become unexported (`insertSeccompArg`) — it's only needed internally by `PrepareForMonitoring` and `Run`. Check if any test files in `sandbox_test` (black-box) use it; if so, keep it exported until those tests are updated.
- The bwrap resolution + version check in `buildSandboxedMonitor` (lines 309-318 of run.go) is removed — `PrepareForMonitoring` handles it, matching what `Sandbox.Run` already does internally.

### What stays the same

- `monitor` and `sandbox` remain separate packages.
- `Sandbox.Run()` for the non-monitored path is unchanged.
- `buildNoSandboxMonitor()` is unchanged (no sandbox involved).
- `monitor.New` signature is unchanged.
- `Sandbox.BuildBwrapArgs()` stays exported — it's used by monitor integration tests that construct bwrap commands directly for testing strace parsing with real bwrap.

### Test changes

- Add a unit test for `PrepareForMonitoring` in `internal/sandbox/sandbox_test.go` (white-box) that verifies the returned `MonitorInput` has correct `SetupExecves` (2 without netPath, 3 with netPath), `FullCommand` starts with the bwrap binary, and `SeccompPipe` is non-nil.
- The existing integration test in `internal/monitor/integration_test.go` that constructs bwrap args via `sandbox.New` + `BuildBwrapArgs` can optionally be updated to use `PrepareForMonitoring` instead, but this is not required since `BuildBwrapArgs` stays exported.
- Run `go test ./...` to verify nothing breaks.

## Verification

```bash
go test ./internal/sandbox/... ./internal/run/... ./internal/monitor/...
go build ./...
golangci-lint run --fix
```
