package monitor

import (
	"io"
	"os"
)

// Export unexported functions for testing.

func (m *Monitor) BuildStraceArgs(tmpPath string, command []string) []string {
	return m.buildStraceArgs(tmpPath, command)
}

// ProcessStraceOutput exports processStraceOutput for testing with synthetic strace data.
func (m *Monitor) ProcessStraceOutput(output io.Reader, logFile *os.File) error {
	return m.processStraceOutput(output, logFile)
}

var MapSyscallToOperation = mapSyscallToOperation

var IsManagedPath = isManagedPath
