## Context

execave currently supports two execution modes: sandboxed (bwrap only) and sandboxed+monitored (bwrap wrapped by strace). When a sandboxed command fails to find a file, it is difficult to diagnose because the sandbox hides the host filesystem view. The `monitor` package already supports direct tracing (empty `bwrapArgs`) but this path is only used in tests.

The new mode — monitored without sandbox (`--no-sandbox --monitor`) — adds a third path: strace traces the command directly on the host, with no bwrap, no seccomp, and no network namespace. The proxy still runs so HTTP traffic is observable.

## Goals / Non-Goals

**Goals:**
- Run command with strace on host, logging all filesystem accesses against config rules (diagnostic only)
- Network proxy starts; HTTP_PROXY/HTTPS_PROXY injected so proxy-aware HTTP traffic is visible in log
- `--no-sandbox` requires `--monitor` (usage error if missing)

**Non-Goals:**
- Enforcement: nothing is denied in `--no-sandbox` mode
- Non-HTTP network tracing: only proxy-aware HTTP traffic is observable (same as sandboxed mode)
- Seccomp tracing: no filter, no SYSCALL log entries

## Decisions

### D1: Require `--monitor` when `--no-sandbox` is used

**Decision:** Error if `--no-sandbox` is used without `--monitor`.

**Rationale:** Running without a sandbox but without monitoring gives no value over running the program directly. Making it an error prevents accidental unsandboxed execution. The user must explicitly opt into monitoring.

**Alternative:** Implicitly enable `--monitor=-` (stderr). Rejected because it hides the explicit opt-in and makes the behavior less obvious.

### D2: Host-side TCP bridge via `tunnel.StartBridge()`

**Decision:** Add `tunnel.StartBridge(udsPath string) (port int, stop func(), error)` that starts a TCP listener on 127.0.0.1:0 and a goroutine bridging TCP → UDS. The runner calls this directly rather than spawning a subprocess.

**Rationale:** In sandboxed mode, the tunnel runs as a subprocess inside the sandbox because the tunnel binary and UDS must be bind-mounted into the sandbox namespace. In unsandboxed mode, both the bridge goroutine and the traced command run on the host — no subprocess or bind-mount is needed. Reusing the bridge logic in-process is simpler and avoids a subprocess that would also be traced by strace.

**Alternative:** Expose the proxy on TCP (change `proxy.Start` to accept TCP). Rejected: changes the proxy interface, requires deciding a port, and affects the sandboxed path unnecessarily.

**Alternative:** Start the tunnel binary as a subprocess outside strace. Rejected: the tunnel subprocess would need its own strace exclusion, and the subprocess lifecycle complicates the runner.

### D3: `extraEnv []string` on `monitor.Monitor`

**Decision:** Add an `extraEnv` field to `monitor.Monitor`. In `Run()`, when non-nil, set `cmd.Env = append(os.Environ(), extraEnv...)` instead of inheriting parent env silently.

**Rationale:** The monitor does not currently support injecting env vars into the traced command. Rather than setting env vars in the execave parent process (global side effect) or passing them through shell escaping in strace args, adding `extraEnv` to the monitor is clean and testable.

**Alternative:** Set HTTP_PROXY in the parent process before starting strace. Rejected: global state mutation, affects the proxy cleanup goroutine if it reads env, and is not reversible without storing old values.

### D4: `noSandbox bool` on `runner.Runner`

**Decision:** Add `noSandbox bool` to `Runner` (set at construction via `New()`). In `Start()`, branch on this flag to skip bwrap resolution, sandbox construction, seccomp filter creation, and tunnel subprocess setup.

**Rationale:** Keeping the flag in the Runner (set once at construction) matches the existing design where `absConfigPath` and `netPath` are also immutable infrastructure. Each `Start()` call reuses the same execution mode.

## Risks / Trade-offs

**Risk: Non-HTTP network traffic is invisible** → The proxy only intercepts HTTP (CONNECT + plain HTTP). Direct TCP connections bypass it. This is the same limitation as sandboxed mode; acceptable for the diagnostic use case.

**Risk: TCP bridge port reuse** → `127.0.0.1:0` lets the kernel pick the port, avoiding conflicts. The bridge starts before strace, so the port is known before the command starts.

**Risk: Bridge goroutine leaks if Stop panics** → `tunnel.StartBridge` returns a `stop func()` that closes the TCP listener and waits for in-flight relays to drain. The runner calls `stop()` in the run goroutine after `monitor.Run()` returns, ensuring cleanup even if the run is cancelled.

### D5: `UNENFORCED` result for all no-sandbox log entries

**Decision:** When running with `--no-sandbox`, every access log entry (FS and network) SHALL carry result `UNENFORCED` instead of `OK` or `DENY`. This is implemented by adding an `unenforced bool` option to `accesslog.Logger` that overrides all results at the logger level, so neither the monitor nor the proxy need to be aware of no-sandbox mode.

**Rationale:** Showing `OK`/`DENY` in no-sandbox mode is misleading: it implies the sandbox made a decision, when in reality nothing was blocked. `UNENFORCED` is unambiguous — it tells the user that the entry was observed but not controlled. Placing the override in the logger (rather than the monitor or proxy) ensures both FS and network entries are covered without duplicating the logic.

**Alternative:** Keep `OK`/`DENY` based on what rules would have decided. Rejected: ambiguous output that looks like enforcement results; users may misread `DENY` as meaning the access was actually blocked.

**Alternative:** Use `OK` for all entries. Rejected: implies the access was permitted by a rule, which is not accurate for paths that have no matching rule.



No migration needed. All changes are additive. The `--no-sandbox` flag is new; existing invocations are unaffected. No config format changes.

## Open Questions

_(none)_
