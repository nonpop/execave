## Context

Execave launches child processes (strace wrapping bwrap, or bwrap directly) via `exec.CommandContext`. When the user presses ctrl-c, SIGINT is delivered to the entire foreground process group. Go's default SIGINT handler terminates the execave process before it can process strace output and write the access log.

The strace output is written to a temp file during execution. After strace exits, `processStraceResults()` reads the temp file and writes the access log. This post-processing step is the one that never runs.

## Goals / Non-Goals

**Goals:**
- Access log is written even when the child process is terminated by SIGINT (ctrl-c).
- Execave's exit code still reflects the child process's exit status.

**Non-Goals:**
- Handling SIGKILL (cannot be caught; data loss is expected).
- Adding a general signal-forwarding framework.
- Changing how strace/bwrap handle signals (they already handle SIGINT correctly).

## Decisions

### Decision: Ignore SIGINT in the Go process using signal.Notify

**Approach:** Call `signal.Notify(sigCh, syscall.SIGINT)` (not `signal.Ignore`) before launching the child process.

**Rationale:** The child process (strace/bwrap) is in the same process group and receives SIGINT directly from the terminal. It handles the signal and exits. The Go process only needs to survive until `cmd.Run()` returns, then process results and exit with the child's exit code.

**Why signal.Notify instead of signal.Ignore:** `signal.Ignore` sets `SIG_IGN` at the OS level, which is inherited by child processes across exec. This would cause strace/bwrap/child to also ignore SIGINT. `signal.Notify` uses the Go runtime's internal handler instead — children get `SIG_DFL` after exec and handle SIGINT normally.

**Alternatives considered:**

1. **Use signal.Ignore instead of signal.Notify.** Rejected because `signal.Ignore` sets `SIG_IGN` at the OS level, which is inherited by child processes across exec — this would cause strace/bwrap/child to also ignore SIGINT.

2. **Put the child in a separate process group** (via `cmd.SysProcAttr.Setpgid`). This would prevent SIGINT from reaching the child, requiring us to forward signals manually. More complex and changes the signal delivery semantics for interactive programs (e.g., shell sessions inside the sandbox).

3. **Restore SIGINT after child exits.** Not needed — execave exits immediately after post-processing. If future code runs after the child exits and needs default SIGINT behavior, this can be added then.

### Decision: Apply signal handling in main, not in sandbox/monitor

**Approach:** Ignore SIGINT once in `runCommand()` before either execution path (monitor or sandbox-only).

**Rationale:** Both paths launch child processes via `cmd.Run()` and need the Go process to survive. Centralizing in `runCommand()` avoids duplicating signal setup across sandbox and monitor packages.

### Decision: Propagate child exit code for signal termination

When strace/bwrap is killed by a signal, `cmd.Run()` returns an `exec.ExitError`. The existing exit code extraction logic already handles this — no changes needed. On Linux, a process killed by signal N exits with code 128+N (SIGINT=2 → exit code 130).

## Risks / Trade-offs

**[Risk: Go process becomes unkillable by ctrl-c]** → The Go process only ignores SIGINT during child execution. After the child exits, the Go process does post-processing and exits on its own. If post-processing hangs, the user can still send SIGTERM or SIGKILL. In practice, post-processing (parsing a temp file) completes in milliseconds.

**[Risk: Interactive programs inside sandbox behave differently]** → No change. The child process still receives SIGINT from the terminal directly. Only the Go wrapper ignores it. The child's interactive behavior is unaffected.

**[Trade-off: SIGINT during non-monitor mode]** → In sandbox-only mode (no `--monitor`), there's no access log to write. However, ignoring SIGINT is still correct: the Go process should exit with the child's exit code, not with Go's default SIGINT exit behavior. This ensures consistent exit code semantics regardless of mode.
