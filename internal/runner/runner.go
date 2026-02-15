// Package runner provides run lifecycle management for monitored sandbox executions.
//
// The Runner encapsulates starting, stopping, and restarting sandbox+monitor runs,
// tracking run status, and managing access logs. Each Start call creates a fresh
// access log and replaces any active run.
package runner

import (
	"context"
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
	initialTermState *term.State // saved at construction for restoration

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
// The cfg parameter is not stored — it's passed to Start for each run to support
// future config editing.
func New(cfg *config.Config, absConfigPath string, netPath *sandbox.NetworkPath) *Runner {
	if cfg == nil {
		panic("New: cfg must not be nil")
	}
	if absConfigPath == "" {
		panic("New: absConfigPath must not be empty")
	}
	if netPath == nil {
		panic("New: netPath must not be nil")
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
		initialTermState: initialTermState,
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

	// Create fresh logger and resolver
	logger := accesslog.New(cfg.ManagedPaths)
	resolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)

	// Notify external components (e.g., network proxy) about the new logger
	if r.OnLoggerChange != nil {
		r.OnLoggerChange(logger)
	}

	// Build sandbox and monitor
	sb := sandbox.New(cfg, r.absConfigPath, r.netPath)
	bwrapArgs := sb.BuildBwrapArgs(command)
	mon := monitor.New(logger, resolver, bwrapArgs, sb.HasNetworkPath())

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
	go r.runInBackground(runCtx, mon, command, done)

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

// runInBackground runs the monitor and updates status when complete.
func (r *Runner) runInBackground(ctx context.Context, mon *monitor.Monitor, command []string, done chan struct{}) {
	defer close(done)

	exitCode, err := mon.Run(ctx, command)

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
	// - The stop button kills the child with SIGKILL (no cleanup chance)
	// - The child exits without restoring terminal settings
	// Without this, the "Press Ctrl-C to exit" prompt is a lie — the user
	// can't actually Ctrl-C because raw mode swallows it as a byte (0x03).
	r.restoreTerminal()

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

	// Clear any TUI artifacts left by the killed process.
	// TUI apps often use alternate screen buffer and don't clean up when killed.
	clearScreen()

	// Print exit notification to terminal
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[execave: process stopped with error: %v]\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "\n[execave: process stopped (exit code: %d)]\n", exitCode)
	}
	fmt.Fprintf(os.Stderr, "[execave: monitor still running. Press Ctrl-C to exit]\n")

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

// clearScreen clears TUI artifacts left by killed processes.
// Many TUI apps use alternate screen buffer and special terminal modes.
// When killed, they don't clean up, leaving artifacts visible.
func clearScreen() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}

	// Write all escape sequences in one call:
	// - Exit alternate screen buffer (CSI ?1049l)
	// - Clear entire screen (CSI 2J)
	// - Move cursor to home position (CSI H)
	// - Show cursor if hidden (CSI ?25h)
	// - Disable focus reporting (CSI ?1004l)
	// - Disable mouse tracking modes (CSI ?1000l through ?1003l)
	// - Reset all terminal modes (CSI m)
	//
	// Focus reporting and mouse tracking are terminal emulator features
	// controlled via escape sequences, not termios flags, so
	// term.Restore() cannot reset them.
	_, _ = fmt.Fprint(os.Stdout, "\x1b[?1049l\x1b[2J\x1b[H\x1b[?25h\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[m")
}
