// Package exitcode extracts exit codes from command run errors.
package exitcode

import (
	"errors"
	"os/exec"
	"syscall"
)

// Extract returns the exit code from a command run error.
// Returns (0, nil) for a nil error.
// Returns (128+signal, nil) for signal-terminated processes.
// Returns (exit code, nil) for processes that exited with a non-zero code.
// Returns (1, err) for errors that are not *exec.ExitError (e.g. failed to start).
func Extract(err error) (int, error) {
	if err == nil {
		return 0, nil
	}

	exitErr := new(exec.ExitError)
	if !errors.As(err, &exitErr) {
		return 1, err
	}

	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if ok && ws.Signaled() {
		// Process was terminated by signal - return 128 + signal number.
		// This matches shell convention (e.g., SIGINT = 2 → exit code 130).
		return 128 + int(ws.Signal()), nil //nolint:mnd // well-known code
	}

	return exitErr.ExitCode(), nil
}
