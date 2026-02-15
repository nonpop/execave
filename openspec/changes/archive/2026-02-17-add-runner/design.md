## Context

The run lifecycle is currently inlined in `cmd/execave/main.go`'s `runMonitored` function: it creates a `statusTracker`, builds a `monitor.Monitor`, calls `mon.Run()` (blocking), then waits for SIGINT. The web UI (`webui.Server`) is a passive observer — it receives a `StatusProvider` and `*accesslog.Logger` and has no way to trigger a new run.

To support start/stop/restart from the web UI, the lifecycle logic needs to move behind an interface that the web server can call.

## Goals / Non-Goals

**Goals:**
- A `runner` component that encapsulates monitored sandbox execution with start/stop control
- Web UI endpoints to trigger start and stop
- Fresh access log on each new run
- The webui depends on the runner for status, run control, and logger access

**Non-Goals:**
- Config editing or draft config (future change)
- Command override from the web UI (command is fixed from CLI args)
- Run history or multi-run tabs
- Persistent state across server restarts

## Decisions

### 1. Runner as a separate package (`internal/runner`)

The runner encapsulates run lifecycle: building the sandbox+monitor, running in a goroutine, tracking status, and managing the access log. It lives in `internal/runner` rather than in `cmd/execave` or `internal/webui`.

Construction takes immutable infrastructure that doesn't change between runs:

```go
func New(cfg *config.Config, absConfigPath string, netPath *sandbox.NetworkPath) *Runner
```

`Start` takes a context and command, and receives the config at call time to support future config editing:

```go
func (r *Runner) Start(ctx context.Context, cfg *config.Config, command []string) error
```

Each `Start` call: stops any active run, creates a fresh `accesslog.Logger`, builds a `sandbox.Sandbox` and `monitor.Monitor`, and runs in a background goroutine. `Start` returns after the goroutine is launched (non-blocking).

**Why separate from webui:** The runner is business logic (sandbox lifecycle). The web UI is presentation (HTTP endpoints). Keeping them separate means the runner can be tested without HTTP and reused by future consumers (e.g., a future CLI-only restart mode).

**Why separate from cmd/execave:** The `statusTracker` currently lives in `cmd/execave` because it was simple orchestration glue. The runner subsumes the status tracker and adds real logic (goroutine management, stop/restart). This belongs in an internal package with proper tests, not in `main`.

### 2. Start always stops the active run

`Start` is unconditional: if a run is active, cancel its context and wait for the goroutine to finish before starting the new one. This avoids races where the web UI's view of run state lags behind reality — the UI just calls Start and it always works.

`Stop` cancels the active run's context and waits. No-op if nothing is running.

The wait in both cases blocks until the monitor goroutine exits. This is bounded: context cancellation triggers process kill, and strace exits shortly after its child.

### 3. Fresh access log per run

Each `Start` creates a new `accesslog.Logger` and replaces the previous one. The runner exposes the current logger via `Logger() *accesslog.Logger`.

The webui currently takes a logger at construction time. With the runner, the logger changes on each run. The web UI needs to handle this — on each status change to "running", it should re-subscribe to the new logger. The SSE endpoint sends a session event that tells the browser to clear its table and reconnect.

**Alternative considered:** Reset the existing logger (clear entries + seen map). Rejected because a `Reset()` must be coordinated with all subscribers — existing SSE connections hold entry cursors that become invalid after reset, and the seen map must be cleared atomically with the entries slice while no `Log()` calls are in flight. Creating a new logger sidesteps all of this: the old logger and its subscribers simply become unreachable, and the webui re-subscribes to the new one on the next status change.

### 4. Runner tracks status internally

The runner tracks run status (idle/running/exited) and notifies subscribers via the existing non-blocking channel pattern. This replaces both the `StatusProvider` interface and the `statusTracker` in `cmd/execave/status.go`.

Status transitions:
- Construction: idle (not running, no exit code)
- `Start` called: running
- Run completes: exited (with exit code and optional error)
- `Stop` called while running: exited (with whatever code the killed process produces)

### 5. WebUI Server depends on Runner

The webui.Server takes a `*runner.Runner` at construction — one dependency instead of the previous two (`StatusProvider` + `*accesslog.Logger`). `StatusProvider` interface is removed. `RunStatus` type moves from `webui` to `runner`.

### 6. Web UI run control endpoints

Two new routes on `webui.Server`:

- `POST /api/start` — calls `runner.Start(ctx, cfg, command)`. Returns 200 on success, 500 on error. Uses the server's context (stored at `Server.Start()` time), not the HTTP request context (which gets canceled immediately after the response is sent).
- `POST /api/stop` — calls `runner.Stop()`. Returns 200 always.

The frontend adds Start/Stop buttons to the status bar. The button label switches between "Start" and "Restart" based on whether the process is running. A status SSE event triggers the label update.

### 7. Refactored main.go orchestration

The runner only applies to monitoring mode. The non-monitoring path (`sb.Run()` directly) is unchanged.

`runMonitored` simplifies to:
1. Create runner
2. Start web UI server (passing runner)
3. Call `runner.Start(ctx, cfg, command)` for the initial run
4. Wait for SIGINT
5. Return the runner's last exit code

The `statusTracker` type in `cmd/execave/status.go` is deleted — the runner subsumes it.

### 8. Terminal handling for restarts

When a process is stopped via context cancellation, it may not fully clean up terminal state. This creates problems when restarting:

**Issue 1: Terminal state corruption** → A killed process may leave the terminal in a bad state (echo disabled, raw mode, etc.). The next process inherits this broken state, making the terminal unusable (e.g., bash with no echo).

**Solution:** Save the initial terminal state at runner construction. Before each `Start`, restore the terminal to this initial state using `term.Restore()`. This ensures each run begins with a clean terminal.

**Issue 2: TUI artifacts** → TUI applications use alternate screen buffers and special modes. When killed, they leave artifacts visible on screen (menus, borders, etc.).

**Solution:** After a run exits, send terminal escape sequences to: exit alternate screen buffer (`\x1b[?1049l`), clear screen (`\x1b[2J`), reset cursor (`\x1b[H`, `\x1b[?25h`), disable focus reporting (`\x1b[?1004l`), disable mouse tracking (`\x1b[?1000l`, `\x1b[?1002l`, `\x1b[?1003l`), and reset modes (`\x1b[m`). Focus reporting and mouse tracking are terminal emulator features controlled via escape sequences, not termios flags, so `term.Restore()` cannot reset them.

**Issue 3: Buffered input leakage** → Input typed while no process is running sits in the terminal's input buffer. When a new process starts, it receives this buffered input, causing confusion (user's debug typing appears in the new bash session).

**Solution:** Before each `Start`, flush the terminal input queue using `ioctl` with `TCFLSH` (`0x540B` on Linux) and `TCIOFLUSH` (2). This discards pending input.

**Issue 4: Lack of visual feedback** → When a process is stopped, there's no immediate indication in the terminal. The user doesn't know if the stop worked or if the terminal is hanging.

**Solution:** After a run exits, print a notification to stderr: `[execave: process stopped (exit code: N)]` followed by `[execave: monitor still running. Press Ctrl-C to exit]`. This gives clear feedback and reminds the user how to exit.

**Issue 5: Foreground process group loss** → Without `--new-session` (Linux 6.2+), the sandboxed process shares the controlling terminal and can call `tcsetpgrp()` to become the foreground process group (e.g., bash does this). When killed, the foreground group is dead, and execave is left as a background group. This causes two problems: (a) terminal ioctls like `tcsetattr` (used by `restoreTerminal`) trigger SIGTTOU, whose default action stops the process; (b) Ctrl-C sends SIGINT to the dead foreground group, so execave never receives it.

**Solution:** Ignore SIGTTOU via `signal.Ignore` early in `runSandboxed`. Must use `signal.Ignore` (not `signal.Notify`): the kernel's `tty_check_change` checks for `SIG_IGN` disposition specifically — a Go runtime handler (`signal.Notify`) does not satisfy `is_ignored()`, causing an infinite SIGTTOU/restart loop on terminal ioctls from a background group. `SIG_IGN` is inherited by children across exec, but this is harmless: interactive shells reset their own signal handlers on startup. After the child exits, call `tcsetpgrp` (ioctl `TIOCSPGRP`) to reclaim the foreground process group before performing any terminal operations.

## Risks / Trade-offs

**Blocking Stop in Start** → `Start` waits for the old run to finish before starting the new one. If the process ignores SIGKILL (zombie), this blocks indefinitely. Mitigation: context cancellation sends SIGKILL via exec.CommandContext, and the kernel guarantees SIGKILL delivery to non-zombie processes. Strace exits after its child, so the goroutine always finishes.

**Logger swap race** → Between the runner replacing the logger and the webui picking up the new one, SSE subscribers could miss the transition. Mitigation: the status change to "running" signals the webui to re-read the logger. The SSE session event tells the browser to clear and reconnect. There's a brief window, but the browser's EventSource reconnection handles it.

**No graceful process termination** → `Stop` cancels the context, which sends SIGKILL (Go's exec.CommandContext default). The process doesn't get a chance to clean up. This is acceptable for the monitoring use case — the user wants to stop and restart quickly, not preserve process state. The runner handles the cleanup consequences (terminal restoration, TUI cleanup, input flushing) to mitigate the impact of abrupt termination.
