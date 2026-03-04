// Package runner provides run lifecycle management for monitored sandbox executions.
//
// The Runner encapsulates starting, stopping, and restarting sandbox+monitor runs,
// tracking run status, and managing access logs. Each Start call creates a fresh
// access log and replaces any active run.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/tunnel"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// RunStatus represents the current state of a monitored run.
type RunStatus struct {
	Running  bool
	ExitCode int
	Error    string // Error message from the run (empty if no error)
	Command  string // Command string for the current/last run
}

// Runner manages the lifecycle of monitored sandbox executions.
//
// The Runner provides start/stop control, status tracking, and access to the
// current access log. Each Start call creates a fresh logger and replaces any
// active run.
//
// All methods are safe for concurrent use.
type Runner struct {
	// Immutable infrastructure (set at construction)
	absConfigPath    string
	netPath          *sandbox.NetworkPath
	interpreterPath  string      // auto-detected ELF interpreter, applied to every cfg in Start
	initialTermState *term.State // saved at construction for restoration
	noSandbox        bool        // when true, skip bwrap/seccomp and trace command directly on host

	// OnLoggerChange is called with the new logger each time Start creates one.
	// This enables external components sharing the logger (e.g., network proxy)
	// to switch to the current run's logger. Must be set before Start is called.
	OnLoggerChange func(*accesslog.Logger)

	mu           sync.RWMutex
	status       RunStatus
	logger       *accesslog.Logger
	cancel       context.CancelFunc
	done         chan struct{} // closed when run goroutine exits
	command      []string      // current/last command
	statusSubs   map[chan struct{}]bool
	statusSubsMu sync.Mutex
}

// New creates a new Runner with the given configuration infrastructure.
//
// The absConfigPath and netPath are immutable and used for all runs.
// netPath may be nil when no network proxy/tunnel is configured.
// noSandbox skips bwrap and seccomp; the command runs directly on the host under strace.
// The cfg parameter is not stored — it's passed to Start for each run to support
// future config editing.
func New(cfg *config.Config, absConfigPath string, netPath *sandbox.NetworkPath, noSandbox bool) *Runner {
	if cfg == nil {
		panic("New: cfg must not be nil")
	}
	if absConfigPath == "" {
		panic("New: absConfigPath must not be empty")
	}
	// Save initial terminal state for restoration between runs
	var initialTermState *term.State
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		state, err := term.GetState(stdinFd)
		if err == nil {
			initialTermState = state
		}
	}

	return &Runner{
		absConfigPath:    absConfigPath,
		netPath:          netPath,
		interpreterPath:  cfg.InterpreterPath,
		initialTermState: initialTermState,
		noSandbox:        noSandbox,
		OnLoggerChange:   nil,
		mu:               sync.RWMutex{},
		status:           RunStatus{Running: false, ExitCode: 0, Error: "", Command: ""},
		logger:           nil,
		cancel:           nil,
		done:             nil,
		command:          nil,
		statusSubsMu:     sync.Mutex{},
		statusSubs:       make(map[chan struct{}]bool),
	}
}

// Status returns the current run status.
func (r *Runner) Status() RunStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// Logger returns the current access log logger.
//
// Returns nil if no run has started yet.
func (r *Runner) Logger() *accesslog.Logger {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.logger
}

// Subscribe registers a channel to receive status change notifications.
//
// The channel receives a non-blocking signal whenever status changes.
// Callers should use Status() to retrieve the current status snapshot.
// Use Unsubscribe to stop receiving updates.
func (r *Runner) Subscribe() chan struct{} {
	r.statusSubsMu.Lock()
	defer r.statusSubsMu.Unlock()
	ch := make(chan struct{}, 1)
	r.statusSubs[ch] = true
	return ch
}

// Unsubscribe removes a previously registered status channel.
func (r *Runner) Unsubscribe(ch chan struct{}) {
	r.statusSubsMu.Lock()
	defer r.statusSubsMu.Unlock()
	delete(r.statusSubs, ch)
}

// Start starts a new monitored sandbox run with the given configuration and command.
//
// If a run is already active, Start stops it first and waits for it to complete.
// Each Start creates a fresh access log and replaces the previous logger.
//
// Start returns after launching the run in a background goroutine.
// Use Status or Subscribe to track run progress.
//
// cfg must not be nil. command must not be empty.
func (r *Runner) Start(ctx context.Context, cfg *config.Config, command []string) error {
	if cfg == nil {
		panic("Start: cfg must not be nil")
	}
	if len(command) == 0 {
		panic("Start: command must not be empty")
	}

	// Stop any active run first
	r.Stop()

	// Restore terminal state to initial state before starting new run
	// This ensures each run starts with a clean terminal, even if the
	// previous run was killed and left the terminal in a bad state
	r.restoreTerminal()

	// Drain any buffered input from stdin
	// This prevents input typed while stopped from leaking into the new run
	drainStdin()

	// Inject the auto-detected interpreter path. Configs loaded via ParseTOML
	// don't include it — the Runner preserves it from startup.
	cfg.InterpreterPath = r.interpreterPath

	// Create fresh logger and resolver; in no-sandbox mode all entries carry UNENFORCED result.
	logger := accesslog.New(cfg.ManagedPaths, r.noSandbox)
	resolver := fsrules.NewAccessResolver(cfg.FSRules, cfg.ManagedPaths)

	// Notify external components (e.g., network proxy) about the new logger
	if r.OnLoggerChange != nil {
		r.OnLoggerChange(logger)
	}

	// Resolve and validate strace binary (always needed).
	stracePath, err := sandbox.ResolveStrace()
	if err != nil {
		return fmt.Errorf("start monitored run: %w", err)
	}

	if warn, verr := sandbox.CheckStraceVersion(stracePath); verr != nil {
		return fmt.Errorf("start monitored run: %w", verr)
	} else if warn != "" {
		fmt.Fprintln(os.Stderr, "execave: warning:", warn)
	}

	var mon *monitor.Monitor
	var bridgeStop func()

	if r.noSandbox {
		mon, bridgeStop, err = r.buildNoSandboxMonitor(ctx, cfg, stracePath, logger, resolver)
		if err != nil {
			return err
		}
	} else {
		mon, err = r.buildSandboxedMonitor(cfg, stracePath, logger, resolver, command)
		if err != nil {
			return err
		}
	}

	// Create context for this run
	runCtx, cancel := context.WithCancel(ctx)

	// Set up run state
	done := make(chan struct{})
	commandStr := strings.Join(command, " ")
	r.mu.Lock()
	r.status = RunStatus{Running: true, ExitCode: 0, Error: "", Command: commandStr}
	r.logger = logger
	r.cancel = cancel
	r.done = done
	r.command = command
	r.mu.Unlock()

	// Notify subscribers
	r.notifyStatus()

	// Start run in background
	go r.runInBackground(runCtx, mon, command, bridgeStop, done)

	return nil
}

// Stop stops the active run and waits for it to complete.
//
// Stop is a no-op if no run is active.
func (r *Runner) Stop() {
	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.mu.Unlock()

	if cancel == nil {
		// No active run
		return
	}

	// Cancel context and wait for goroutine to finish
	cancel()
	<-done
}

// buildNoSandboxMonitor creates a Monitor and optional bridge stop function for no-sandbox mode.
// Unsandboxed mode: trace command directly on the host without bwrap or seccomp.
// Syscall maps are still built and passed so blocked syscalls are traced and logged.
func (r *Runner) buildNoSandboxMonitor(ctx context.Context, cfg *config.Config, stracePath string, logger *accesslog.Logger, resolver *fsrules.AccessResolver) (*monitor.Monitor, func(), error) {
	allowedSyscalls, blockedSyscalls := buildSyscallMaps(cfg)
	var extraEnv []string
	var bridgeStop func()
	if r.netPath != nil {
		port, stop, err := tunnel.StartBridge(ctx, r.netPath.UDSPath)
		if err != nil {
			return nil, nil, fmt.Errorf("start bridge for no-sandbox run: %w", err)
		}
		bridgeStop = stop
		proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)
		extraEnv = []string{
			"HTTP_PROXY=" + proxyURL,
			"HTTPS_PROXY=" + proxyURL,
			"http_proxy=" + proxyURL,
			"https_proxy=" + proxyURL,
		}
	}
	mon := monitor.New("", stracePath, logger, resolver, nil, false, nil, blockedSyscalls, allowedSyscalls, extraEnv)
	return mon, bridgeStop, nil
}

// buildSandboxedMonitor creates a Monitor for sandboxed mode.
// Sandboxed mode: resolve bwrap, build sandbox args and seccomp filter.
func (r *Runner) buildSandboxedMonitor(cfg *config.Config, stracePath string, logger *accesslog.Logger, resolver *fsrules.AccessResolver, command []string) (*monitor.Monitor, error) {
	bwrapPath, err := sandbox.ResolveBwrap()
	if err != nil {
		return nil, fmt.Errorf("start monitored run: %w", err)
	}

	if warn, verr := sandbox.CheckBwrapVersion(bwrapPath); verr != nil {
		return nil, fmt.Errorf("start monitored run: %w", verr)
	} else if warn != "" {
		fmt.Fprintln(os.Stderr, "execave: warning:", warn)
	}

	sb := sandbox.New(cfg, r.absConfigPath, r.netPath)
	bwrapArgs := sb.BuildBwrapArgs(command)

	allowedSyscalls, blockedSyscalls := buildSyscallMaps(cfg)
	seccompPipe, err := seccomp.FilterPipe(allowedSyscalls)
	if err != nil {
		return nil, fmt.Errorf("create seccomp filter for monitored run: %w", err)
	}

	return monitor.New(bwrapPath, stracePath, logger, resolver, bwrapArgs, sb.HasNetworkPath(), seccompPipe, blockedSyscalls, allowedSyscalls, nil), nil
}

// runInBackground runs the monitor and updates status when complete.
// bridgeStop, if non-nil, is called after mon.Run returns to stop the host-side TCP bridge.
func (r *Runner) runInBackground(ctx context.Context, mon *monitor.Monitor, command []string, bridgeStop func(), done chan struct{}) {
	defer close(done)

	exitCode, err := mon.Run(ctx, command)

	if bridgeStop != nil {
		bridgeStop()
	}

	// Reclaim the foreground process group before any terminal operations.
	// Without --new-session (Linux 6.2+), the sandboxed process can call
	// tcsetpgrp() to become the foreground group. When it dies, execave is
	// left as a background group. Without reclaiming, Ctrl-C won't reach
	// execave (SIGINT goes to the dead foreground group) and terminal
	// ioctls would trigger SIGTTOU.
	reclaimForeground()

	// Restore terminal state immediately after the child exits.
	// The child may have left the terminal in raw mode (ISIG disabled),
	// which prevents Ctrl-C from generating SIGINT. This happens when:
	// - Stop() kills the child with SIGKILL (no cleanup chance)
	// - The child exits without restoring terminal settings
	r.restoreTerminal()

	// Clear any TUI artifacts left by the killed process.
	// TUI apps often use alternate screen buffer and don't clean up when killed.
	conditionalClearScreen()

	commandStr := strings.Join(command, " ")
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	r.mu.Lock()
	r.status = RunStatus{Running: false, ExitCode: exitCode, Error: errMsg, Command: commandStr}
	r.cancel = nil
	r.done = nil
	r.mu.Unlock()

	// Print exit notification to terminal
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[execave: process stopped with error: %v]\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "\n[execave: process stopped (exit code: %d)]\n", exitCode)
	}
	r.notifyStatus()
}

// notifyStatus sends a notification signal to all subscribers (non-blocking).
func (r *Runner) notifyStatus() {
	r.statusSubsMu.Lock()
	defer r.statusSubsMu.Unlock()

	for ch := range r.statusSubs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// restoreTerminal restores the terminal to the initial state saved at construction.
// This is needed because a killed process may leave the terminal in a bad state
// (e.g., echo disabled, raw mode enabled). We restore the terminal to the state
// it was in before any runs started.
func (r *Runner) restoreTerminal() {
	if r.initialTermState == nil {
		return // Not a terminal or couldn't save state
	}

	stdinFd := int(os.Stdin.Fd())
	_ = term.Restore(stdinFd, r.initialTermState)
}

// buildSyscallMaps creates the allowed and blocked syscall maps from config rules.
// allowed contains syscalls explicitly permitted by syscall:allow rules.
// blocked contains all remaining ruleable syscalls not covered by allow rules.
// Defense-in-depth syscalls are excluded — they are blocked silently by the BPF
// filter without monitor tracing.
func buildSyscallMaps(cfg *config.Config) (map[string]bool, map[string]bool) {
	allowed := make(map[string]bool, len(cfg.SyscallAllowRules))
	for _, name := range cfg.SyscallAllowRules {
		allowed[name] = true
	}
	blocked := make(map[string]bool)
	for _, name := range seccomp.RuleableSyscallNames() {
		if !allowed[name] {
			blocked[name] = true
		}
	}
	return allowed, blocked
}

// drainStdin drains any buffered input from stdin.
// This prevents input typed while no process is running from being sent to the
// next process that starts. We use tcflush (TCIOFLUSH) to discard both input
// and output queues.
func drainStdin() {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return
	}

	// Use tcflush via ioctl to discard terminal I/O queues
	// TCFLSH = 0x540B on Linux (tcflush ioctl request)
	// TCIOFLUSH = 2 (discard both input and output queues)
	const TCFLSH = 0x540B
	const TCIOFLUSH = 2
	//nolint:dogsled // syscall.Syscall returns (r1, r2, errno); none needed for tcflush
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(stdinFd),
		TCFLSH,
		TCIOFLUSH,
	)
}

// reclaimForeground sets execave's process group as the terminal's foreground
// process group. Without --new-session (Linux 6.2+), the sandboxed process can
// call tcsetpgrp() to take over the foreground group. When it dies, execave is
// left as a background group, which means Ctrl-C won't deliver SIGINT to
// execave and terminal ioctls would trigger SIGTTOU.
//
// Requires SIGTTOU to be caught/ignored by the caller, since tcsetpgrp from a
// background process group generates SIGTTOU.
func reclaimForeground() {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return
	}

	pgrp := int32(syscall.Getpgrp()) //nolint:gosec // pid_t fits in int32
	// TIOCSPGRP = 0x5410 on Linux (tcsetpgrp ioctl)
	const TIOCSPGRP = 0x5410
	//nolint:dogsled // syscall.Syscall returns (r1, r2, errno); none needed here
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(stdinFd),
		TIOCSPGRP,
		uintptr(unsafe.Pointer(&pgrp)), //#nosec G103 -- passing pid_t to kernel ioctl
	)
}

// conditionalClearScreen clears TUI artifacts left by killed processes, but only
// when the terminal's alternate screen is actually active. This preserves output
// from regular commands (ls, git, etc.) that never enter alt screen, while still
// cleaning up after TUI apps that were killed before they could restore the terminal.
func conditionalClearScreen() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	// Always restore these — harmless no-ops for regular apps, necessary for killed TUIs.
	// Focus reporting and mouse tracking are controlled via escape sequences, not termios
	// flags, so term.Restore() cannot reset them. CSI ?25h shows cursor, CSI m resets attrs.
	_, _ = fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[m")
	// Only exit alt screen and clear if the terminal reports it is actually active.
	// If stdin is not a terminal we cannot query, so fall back to unconditional cleanup.
	if !term.IsTerminal(int(os.Stdin.Fd())) || queryAltScreen() {
		_, _ = fmt.Fprint(os.Stdout, "\x1b[?1049l\x1b[2J\x1b[H")
	}
}

// queryAltScreen queries the terminal for the alt screen state via DECRQM
// (DEC Request Mode, CSI ? 1049 $ p). The terminal responds with
// CSI ? 1049 ; <value> $ y where value 1 = active, 2 = inactive.
//
// Returns true if alt screen is active. Returns false on error, timeout,
// or when stdin is not a terminal. Conservative: favors preserving output.
func queryAltScreen() bool {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return false
	}

	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return false
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	// Send DECRQM query for alt screen (private mode 1049).
	if _, err := fmt.Fprint(os.Stdout, "\x1b[?1049$p"); err != nil {
		return false
	}

	return parseAltScreenResponse(readTerminalResponse(stdinFd))
}

// readTerminalResponse reads a DECRQM response from the terminal with timeout.
// Uses poll to avoid blocking indefinitely on terminals that don't support DECRQM.
// Initial timeout is 100ms; subsequent polls use 10ms to collect remaining bytes.
func readTerminalResponse(stdinFd int) string {
	var buf [32]byte
	total := 0
	pollFds := []unix.PollFd{{Fd: int32(stdinFd), Events: unix.POLLIN}} //nolint:gosec // stdinFd fits in int32
	timeout := 100
	for total < len(buf) {
		n, pollErr := unix.Poll(pollFds, timeout)
		if errors.Is(pollErr, syscall.EINTR) {
			continue
		}
		if pollErr != nil || n == 0 {
			break
		}
		nr, readErr := syscall.Read(stdinFd, buf[total:])
		if readErr != nil || nr == 0 {
			break
		}
		total += nr
		// Response ends with "$y" — stop reading once complete.
		if total >= 2 && buf[total-2] == '$' && buf[total-1] == 'y' {
			break
		}
		timeout = 10
	}
	return string(buf[:total])
}

// parseAltScreenResponse parses a DECRQM response for private mode 1049.
// Expected format: ESC [ ? 1 0 4 9 ; <value> $ y
// Returns true if <value> is '1' (set/active) or '3' (permanently set).
func parseAltScreenResponse(resp string) bool {
	idx := strings.Index(resp, "?1049;")
	if idx < 0 {
		return false
	}
	valueIdx := idx + len("?1049;")
	if valueIdx >= len(resp) {
		return false
	}
	v := resp[valueIdx]
	return v == '1' || v == '3'
}
