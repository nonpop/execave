## Context

The monitor currently writes strace output to a temp file, waits for the child to exit, then batch-processes the file to produce access log entries. The proxy already writes network log entries in real-time during execution. An upcoming interactive web view needs to tail the access log file while the sandbox is running.

The access log writer (`accesslog.Logger`) takes an `io.Writer` and is agnostic to timing — callers decide when to call `Log()`. The monitor's `processStraceOutput` reads from an `io.Reader` and is agnostic to the source. The change is primarily about plumbing: how strace output reaches the monitor, and when the monitor processes it.

## Goals / Non-Goals

**Goals:**
- Access log entries written as syscalls occur, visible to external readers (e.g. `tail -f`) during sandbox execution
- Minimal change to existing parsing and logging logic
- Thread-safe logger (proxy and monitor now write concurrently)

**Non-Goals:**
- Structured/machine-readable log format (future work for the web view)
- Real-time notifications or push mechanism (external readers poll/tail the file)
- Changes to strace parsing, syscall mapping, or rule resolution

## Decisions

### 1. Pipe strace output through an os.Pipe instead of a temp file

Create an `os.Pipe()`, pass the write end to strace via `ExtraFiles` (becomes fd 3 in the child process), and use `-o /proc/self/fd/3`. A goroutine reads from the pipe's read end and calls the existing `processStraceOutput`.

**Rationale:** `processStraceOutput` already reads from `io.Reader` line by line. Changing the source from a file to a pipe requires no changes to parsing logic. The pipe naturally provides EOF when strace exits (all write-end copies close), so the goroutine terminates cleanly.

**Alternatives considered:**
- *Tail the temp file*: Requires polling or inotify, partial-line handling, and a "done" signal. More complex with more edge cases.
- *strace `-o |command`*: Spawns a shell subprocess. Fragile, harder to manage lifecycle.

**Threat analysis:** This changes how strace output is delivered, not how it's parsed or how rules are evaluated. The same bytes go through the same parsing path. If the pipe fails (broken pipe, full buffer), strace blocks or errors — the sandbox continues running but monitoring may be incomplete. This is fail-safe: the sandbox itself is unaffected.

Pipe buffer (64KB–1MB on Linux) is sufficient. Our processing (regex + map lookup + file write) is far faster than strace's output rate.

### 2. Unbuffered file writes for immediate visibility

Replace `bufio.NewWriter` wrapping `os.File` with direct `os.File` writes. Each `Logger.Log()` call writes one line (~60–100 bytes) via `fmt.Fprintln`, which translates to a single `write()` syscall visible immediately to external readers.

**Rationale:** After deduplication, total unique entries are typically tens to hundreds. The overhead of one syscall per entry is negligible. Removing the `bufio.Writer` eliminates the flush-on-cleanup requirement and makes entries visible without explicit flushing.

**Alternatives considered:**
- *Keep bufio, flush per entry*: Adds complexity (flush call, error handling) for the same result.
- *Line-buffered writer wrapper*: Custom `io.Writer` that flushes on `\n`. Over-engineered for this use case.

### 3. Add sync.Mutex to Logger

The proxy and monitor now call `Logger.Log()` concurrently (previously they never overlapped because monitor ran post-exit). The `seen` map is a shared mutable resource. Add a `sync.Mutex` to `Logger` that protects `Log()`.

**Rationale:** Simple, correct. Lock contention is negligible — proxy handles a few network entries, monitor handles deduplicated filesystem entries. A mutex is the standard Go approach for this pattern.

**Threat analysis:** Without the mutex, concurrent map access causes a data race. Worst case: duplicate entries (benign for logging) or a map panic (crashes the process, which is fail-safe). The mutex eliminates both.

### 4. Restructure Monitor.Run for concurrent processing

Current flow:
1. Create temp file → 2. Run strace (writes to file) → 3. Wait for exit → 4. Read file → 5. Process entries

New flow:
1. Create pipe (pr, pw) → 2. Start strace with `-o /proc/self/fd/3`, pw as ExtraFiles → 3. Close pw in parent → 4. Start goroutine: read pr, call processStraceOutput → 5. cmd.Wait() → 6. Wait for goroutine (pipe EOF → goroutine returns) → 7. Return exit code and any processing error

The `processStraceOutput` method is unchanged — it reads from an `io.Reader`.

**Error handling:** The goroutine sends its error through a channel. After cmd.Wait(), the caller reads the channel to get any processing error. If both strace and processing fail, the strace error (exit code) takes priority since it represents the user's command result.

### 5. Keep SIGINT handling

The existing SIGINT trap in `main.go` remains necessary. After Ctrl-C, the child dies, strace outputs final lines, then exits. The processing goroutine needs to drain remaining pipe data before the Go process exits. Without the SIGINT trap, the Go process would die before the goroutine finishes.

The comment explaining why SIGINT is trapped should be updated to reflect that it protects pipe draining rather than full post-processing.

## Risks / Trade-offs

**Pipe backpressure slows strace** → If the processing goroutine can't keep up, the pipe buffer fills and strace blocks. This would slow the traced process. Mitigation: processing is fast (regex + map lookup + short write). In practice, strace's own overhead dominates. Acceptable trade-off.

**Strace compatibility with /proc/self/fd/N** → strace opens the `-o` path as a regular file. `/proc/self/fd/3` is a symlink to the pipe. This works on Linux (strace writes sequentially, no seeks). Not portable to non-Linux, but execave is Linux-only.

**Concurrent Logger access** → Adding a mutex is a small API behavior change. The Logger was previously not thread-safe. Callers that relied on single-threaded access are unaffected (mutex is a no-op without contention). No external API change.
