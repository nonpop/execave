// Package exitcode extracts process exit codes from [exec.Cmd.Wait] errors.
package exitcode

import (
	"errors"
	"os/exec"
	"syscall"
)

// Extract returns the exit code from an [exec.Cmd.Wait] error.
//
//   - nil error → (0, nil)
//   - [*exec.ExitError] with signal → (128+signal, nil), per POSIX shell convention
//   - [*exec.ExitError] with exit code → (code, nil)
//   - other error → (1, err)
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
