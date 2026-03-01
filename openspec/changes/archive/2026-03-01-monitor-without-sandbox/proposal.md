## Why

When an application fails inside the sandbox, the root cause is often difficult to diagnose: the sandboxed filesystem may be missing ancestor directories, library search paths, or other paths the app probes before reaching the file it actually needs. Users need a way to run the program without bwrap but with strace monitoring so they can observe every real filesystem access — including paths that would be denied in the sandbox — and compare them against their rules.

## What Changes

- Add `--no-sandbox` CLI flag that enables strace-based access monitoring without launching bwrap
- `--no-sandbox` requires `--monitor` to also be specified (error if not)
- The sandboxed command runs natively on the host: full filesystem access, no network namespace isolation, no seccomp filter
- Network proxy still starts; a host-side TCP bridge is started and HTTP_PROXY/HTTPS_PROXY are injected into the traced command's environment so HTTP network access is still observable
- Config rules are still loaded; all log entries use result `UNENFORCED` (a new result type) to make it unambiguous that no enforcement took place — not OK/DENY based on what rules would have decided
- Add `tunnel.StartBridge()` to start a TCP-to-UDS bridge as a host-side goroutine (without running a subprocess)
- Add `extraEnv []string` to `monitor.Monitor` so the runner can inject HTTP_PROXY/HTTPS_PROXY into the strace-traced command's environment

## Playbooks

### New Playbooks

_(none)_

### Modified Playbooks

- `monitoring-access`: add use case for `--no-sandbox --monitor` to observe native accesses and diagnose sandbox configuration issues

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `runner`: add requirement for unsandboxed run mode (noSandbox skips bwrap, seccomp, network namespace; starts host-side TCP bridge; injects HTTP_PROXY env vars)
- `monitor`: add requirement for injecting extra environment variables into the strace-traced command

## Impact

- `cmd/execave/main.go`: new `--no-sandbox` flag
- `internal/runner/runner.go`: new `noSandbox bool` field and mode
- `internal/tunnel/tunnel.go`: new `StartBridge()` function
- `internal/monitor/monitor.go`: new `extraEnv []string` field
- No changes to config format, bwrap invocation path, rule resolution, or permission checks for the existing sandboxed path
- Security impact: `--no-sandbox` is explicitly unsandboxed; it does not weaken the existing sandbox. No trust boundary expansion for the sandboxed path. The host-side TCP bridge is equivalent to the tunnel already running inside the sandbox.
