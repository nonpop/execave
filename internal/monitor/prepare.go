package monitor

import (
	"fmt"
	"os"
	"strings"

	"github.com/nonpop/execave/internal/syscallrules"
)

// MonitoredCommand holds a prepared strace invocation.
// Call [MonitoredCommand.Started] after cmd.Start, or [MonitoredCommand.Abort] on error.
type MonitoredCommand struct {
	StracePath   string     // Absolute path to strace.
	Args         []string   // Complete strace args (excluding binary name).
	ExtraFiles   []*os.File // File descriptors to pass to the child.
	StraceReader *os.File   // Read end of the strace output pipe.

	straceW   *os.File
	extraFile *os.File
}

// Prepare creates a strace output pipe and builds the strace command.
// stracePath and command must not be empty (panics otherwise).
// extraFile is forwarded to the child; nil means none.
// syscallResolver adds syscall names to the trace expression; nil means file ops only.
func Prepare(stracePath string, command []string, extraFile *os.File, syscallResolver *syscallrules.Resolver, baseFD int) (*MonitoredCommand, error) {
	if stracePath == "" {
		panic("execave bug: monitor prepared without strace path")
	}
	if len(command) == 0 {
		panic("execave bug: monitor prepared with no command")
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

// Started closes parent-side pipe ends after cmd.Start has handed duplicates
// to the child. Must be called exactly once after a successful cmd.Start.
func (p *MonitoredCommand) Started() {
	if err := p.straceW.Close(); err != nil {
		panic("execave bug: close strace pipe after start: " + err.Error())
	}
	if p.extraFile != nil {
		if err := p.extraFile.Close(); err != nil {
			panic("execave bug: close extra file after start: " + err.Error())
		}
	}
}

// Abort closes all pipe ends. Call instead of Started when cmd.Start fails.
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
