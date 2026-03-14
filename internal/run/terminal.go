package run

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// drainStdin drains any buffered input from stdin.
// This prevents input typed while no process is running from being sent to the
// next process that starts. We use tcflush (TCIOFLUSH) to discard both input
// and output queues.
func drainStdin() {
	stdinFd := int(os.Stdin.Fd()) //nolint:gosec // G115 -- file descriptors are small non-negative ints
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
		uintptr(stdinFd), //nolint:gosec // G115 -- stdinFd was obtained from Fd(), safe to pass to syscall
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
	stdinFd := int(os.Stdin.Fd()) //nolint:gosec // G115 -- file descriptors are small non-negative ints
	if !term.IsTerminal(stdinFd) {
		return
	}

	pgrp := int32(syscall.Getpgrp()) //nolint:gosec // pid_t fits in int32
	// TIOCSPGRP = 0x5410 on Linux (tcsetpgrp ioctl)
	const TIOCSPGRP = 0x5410
	//nolint:dogsled // syscall.Syscall returns (r1, r2, errno); none needed here
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(stdinFd), //nolint:gosec // G115 -- stdinFd was obtained from Fd(), safe to pass to syscall
		TIOCSPGRP,
		uintptr(unsafe.Pointer(&pgrp)), //#nosec G103 -- passing pid_t to kernel ioctl
	)
}

// conditionalClearScreen clears TUI artifacts left by killed processes, but only
// when the terminal's alternate screen is actually active. This preserves output
// from regular commands (ls, git, etc.) that never enter alt screen, while still
// cleaning up after TUI apps that were killed before they could restore the terminal.
func conditionalClearScreen() {
	if !term.IsTerminal(int(os.Stdout.Fd())) { //nolint:gosec // G115 -- file descriptors are small non-negative ints
		return
	}
	// Always restore these — harmless no-ops for regular apps, necessary for killed TUIs.
	// Focus reporting and mouse tracking are controlled via escape sequences, not termios
	// flags, so term.Restore() cannot reset them. CSI ?25h shows cursor, CSI m resets attrs.
	_, _ = fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[m")
	// Only exit alt screen and clear if the terminal reports it is actually active.
	// If stdin is not a terminal we cannot query, so fall back to unconditional cleanup.
	if queryAltScreen() {
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
	stdinFd := int(os.Stdin.Fd()) //nolint:gosec // G115 -- file descriptors are small non-negative ints
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

// saveTerminalState saves the current terminal state and returns a function
// that restores it. Call the returned function via defer to ensure the terminal
// is restored even if the sandboxed process leaves it in a bad state.
func saveTerminalState() func() {
	stdinFd := int(os.Stdin.Fd()) //nolint:gosec // G115 -- file descriptors are small non-negative ints
	if !term.IsTerminal(stdinFd) {
		return func() {}
	}
	oldState, err := term.GetState(stdinFd)
	if err != nil {
		// IsTerminal just confirmed stdin is a terminal; GetState uses the
		// same ioctl so failure here means the fd was closed concurrently.
		panic(fmt.Sprintf("execave bug: terminal state query failed after IsTerminal: %v", err))
	}
	// Ignore restore errors - terminal is already in unknown state.
	return func() { _ = term.Restore(stdinFd, oldState) }
}
