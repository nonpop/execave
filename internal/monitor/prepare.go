// Package monitor provides strace setup and output processing for filesystem and syscall access logging.
package monitor

import (
	"fmt"
	"os"
	"strings"

	"github.com/nonpop/execave/internal/syscallrules"
)

// MonitoredCommand holds the strace command setup ready for exec.Cmd construction.
// Call Started after cmd.Start succeeds, or Abort to clean up on error.
type MonitoredCommand struct {
	// StracePath is the absolute path to strace.
	StracePath string
	// Args are the complete strace args (not including the binary name).
	Args []string
	// ExtraFiles are the additional file descriptors to pass to the child process.
	ExtraFiles []*os.File
	// StraceReader is the read end of the strace output pipe.
	StraceReader *os.File

	straceW   *os.File
	extraFile *os.File
}

// Prepare creates a pipe for strace output, builds strace arguments, and returns
// a PreparedStrace ready for exec.Cmd construction.
// stracePath must not be empty.
// command must not be empty.
// extraFile is an optional file descriptor forwarded to the child process; nil means none.
// syscallResolver controls which additional syscalls are traced; nil disables syscall tracing.
// baseFD is the file descriptor number for the first entry in ExtraFiles. The caller must place
// ExtraFiles so that they start at this FD.
func Prepare(stracePath string, command []string, extraFile *os.File, syscallResolver *syscallrules.Resolver, baseFD int) (*MonitoredCommand, error) {
	if stracePath == "" {
		panic("stracePath must not be empty")
	}
	if len(command) == 0 {
		panic("command must not be empty")
	}

	straceR, straceW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create pipe for strace output: %w", err)
	}

	extraFiles := []*os.File{}
	if extraFile != nil {
		extraFiles = append(extraFiles, extraFile)
	}
	straceFD := baseFD + len(extraFiles)
	extraFiles = append(extraFiles, straceW)

	args := buildStraceArgs(command, straceFD, syscallResolver)

	return &MonitoredCommand{
		StracePath:   stracePath,
		Args:         args,
		ExtraFiles:   extraFiles,
		StraceReader: straceR,
		straceW:      straceW,
		extraFile:    extraFile,
	}, nil
}

// Started closes parent-side pipe ends after cmd.Start has handed duplicates to the child.
// straceW must be closed or the reader goroutine deadlocks waiting for EOF.
// extraFile must be closed or each call leaks a file descriptor.
// Started must be called after a successful cmd.Start.
//
// This is a separate method rather than part of construction because MonitoredCommand
// does not own process creation: the caller constructs exec.Cmd, calls cmd.Start,
// and then calls Started to close the parent-side ends that the child now holds.
func (p *MonitoredCommand) Started() {
	if err := p.straceW.Close(); err != nil {
		panic("close strace pipe write end: " + err.Error())
	}
	if p.extraFile != nil {
		if err := p.extraFile.Close(); err != nil {
			panic("close extra file: " + err.Error())
		}
	}
}

// Abort closes all pipe ends on an error path, before the child has started.
func (p *MonitoredCommand) Abort() {
	_ = p.StraceReader.Close()
	_ = p.straceW.Close()
}

// buildStraceArgs constructs the strace argument list for tracing command.
// straceFD is the file descriptor number for strace output in the child process.
// syscallResolver controls which additional syscall names are traced; nil means file ops only.
func buildStraceArgs(command []string, straceFD int, syscallResolver *syscallrules.Resolver) []string {
	// Build trace expression: always trace file ops + fchdir.
	// When syscall tracing is active, also trace monitored syscall names.
	traceExpr := "trace=file,fchdir"
	if syscallResolver != nil {
		names := syscallResolver.Names()
		if len(names) > 0 {
			traceExpr += "," + strings.Join(names, ",")
		}
	}

	straceArgs := []string{
		"-f",            // Follow forks
		"-y",            // Print paths for file descriptors
		"-e", traceExpr, // File operations + blocked syscalls
		"-s", "0", // Don't capture string arguments
		"-o", fmt.Sprintf("/proc/self/fd/%d", straceFD), // Output to pipe
		"-qq", // Suppress strace info messages
		"--",
	}

	straceArgs = append(straceArgs, command...)
	return straceArgs
}
