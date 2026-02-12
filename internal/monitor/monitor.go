// Package monitor wraps command execution with strace to log filesystem access.
package monitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/fsrules"
)

// Monitor wraps command execution with strace to log filesystem access.
type Monitor struct {
	resolver       *fsrules.Resolver
	logger         *accesslog.Logger
	bwrapArgs      []string // strace wraps bwrap
	hasNetworkPath bool     // tunnel adds an extra execve to setup
}

// OperationType classifies filesystem operations as read or write.
type OperationType string

const (
	// OperationIgnored indicates a syscall we intentionally ignore.
	OperationIgnored OperationType = "IGNORED"
	// OperationRead represents read operations (stat, open for read, etc).
	OperationRead OperationType = "READ"
	// OperationWrite represents write operations (write, unlink, mkdir, etc).
	OperationWrite OperationType = "WRITE"
)

// New creates a new Monitor.
// bwrapArgs configures sandbox integration. If empty, strace traces the command directly.
// hasNetworkPath indicates whether the sandbox has a network tunnel (adds an extra execve to setup).
func New(logger *accesslog.Logger, resolver *fsrules.Resolver, bwrapArgs []string, hasNetworkPath bool) *Monitor {
	return &Monitor{
		logger:         logger,
		resolver:       resolver,
		bwrapArgs:      bwrapArgs,
		hasNetworkPath: hasNetworkPath,
	}
}

// Run executes a command with strace monitoring.
func (m *Monitor) Run(ctx context.Context, command []string) (int, error) {
	if _, err := exec.LookPath("strace"); err != nil {
		return 1, fmt.Errorf("strace not found in PATH: %w", err)
	}

	// Create pipe for strace output: strace writes to straceW, we read from straceR
	straceR, straceW, err := os.Pipe()
	if err != nil {
		return 1, fmt.Errorf("create pipe for strace output: %w", err)
	}

	// Build strace command with pipe write end as ExtraFiles[0] (becomes fd 3 in child)
	const stracePipeFD = 3
	straceArgs := m.buildStraceArgs(command, stracePipeFD)
	cmd := exec.CommandContext(ctx, "strace", straceArgs...) // #nosec G204 -- args built from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{straceW}

	if err := cmd.Start(); err != nil {
		_ = straceR.Close()
		_ = straceW.Close()
		return 1, fmt.Errorf("start strace: %w", err)
	}

	// Close write end in parent - strace child has its own copy.
	// If this fails, the pipe never gets EOF and the reader goroutine deadlocks.
	if err := straceW.Close(); err != nil {
		panic("close strace pipe write end: " + err.Error())
	}

	// Process strace output in goroutine while child runs
	processingErrCh := make(chan error, 1)
	go func() {
		processingErrCh <- m.processStraceOutput(straceR)
		_ = straceR.Close()
	}()

	// Wait for strace (and traced command) to exit
	err = cmd.Wait()
	exitCode, exitErr := extractExitCode(err)
	if exitErr != nil {
		return exitCode, exitErr
	}

	// Wait for processing goroutine to finish (it drains remaining pipe data)
	processingErr := <-processingErrCh
	if processingErr != nil {
		return exitCode, fmt.Errorf("process strace output: %w", processingErr)
	}

	return exitCode, nil
}

// extractExitCode determines the exit code from a command error.
// Returns 0 if no error, or the exit code if the command failed.
// Returns an error if the command could not be started at all.
func extractExitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}

	exitErr := new(exec.ExitError)
	if !errors.As(err, &exitErr) {
		return 1, fmt.Errorf("execute strace: %w", err)
	}

	// Command ran but exited with non-zero code or signal
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if ok && ws.Signaled() {
		// Process was terminated by signal - return 128 + signal number
		// This matches shell convention (e.g., SIGINT = 2 → exit code 130)
		return 128 + int(ws.Signal()), nil //nolint: mnd // well-known code
	}

	return exitErr.ExitCode(), nil
}

func (m *Monitor) buildStraceArgs(command []string, outputFD int) []string {
	straceArgs := []string{
		"-f",               // Follow forks
		"-y",               // Print paths for file descriptors
		"-e", "trace=file", // Only file operations
		"-s", "0", // Don't capture string arguments
		"-o", fmt.Sprintf("/proc/self/fd/%d", outputFD), // Output to pipe
		"-qq", // Suppress strace info messages
		"--",
	}

	if len(m.bwrapArgs) > 0 {
		// strace wraps bwrap: strace [args] -- bwrap [args] -- command
		// bwrapArgs includes both sandbox config and the command to execute
		straceArgs = append(straceArgs, "bwrap")
		straceArgs = append(straceArgs, m.bwrapArgs...)
	} else {
		// No sandbox (testing only) - trace command directly
		straceArgs = append(straceArgs, command...)
	}

	return straceArgs
}

// processStraceOutput parses strace output and writes access log entries.
func (m *Monitor) processStraceOutput(output io.Reader) error {
	scanner := bufio.NewScanner(output)
	parser := newStraceParser()

	// When bwrap is used, strace captures bwrap's sandbox setup (namespace,
	// mount, pivot_root) before the user command starts. The strace output
	// contains execve calls for setup: bwrap's own (first), optionally the
	// tunnel (second when net rules present), and the user command (last).
	// Skip all lines until the final setup execve.
	inSetup := len(m.bwrapArgs) > 0
	expectedExecves := 2
	if m.hasNetworkPath {
		expectedExecves = 3
	}
	seenExecves := 0

	for scanner.Scan() {
		line := scanner.Text()

		syscall, path, ok := parser.parseLine(line)
		if !ok {
			continue // not a relevant syscall line (e.g., signal info, exit status)
		}

		if inSetup {
			if syscall == "execve" || syscall == "execveat" {
				seenExecves++
			}
			if seenExecves < expectedExecves {
				continue
			}
			inSetup = false
			// Fall through: log the user command's execve as a READ
		}

		if err := m.processAccessEntry(syscall, path, line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan strace output: %w", err)
	}
	return nil
}

func (m *Monitor) processAccessEntry(syscall, path, line string) error {
	opType := mapSyscallToOperation(syscall, line)
	if opType == OperationIgnored {
		return nil
	}

	cleanPath := normalizePath(path)

	// Handle relative paths specially - we can't resolve them without cwd tracking,
	// but log them so the user knows something was accessed.
	if !filepath.IsAbs(cleanPath) {
		return m.handleRelativePath(opType, cleanPath)
	}

	operation := fsrules.OperationRead
	if opType == OperationWrite {
		operation = fsrules.OperationWrite
	}

	result := m.resolver.CheckAccess(cleanPath, operation)

	// If symlink chain is unresolvable (entered managed path), log as UNKNOWN
	if result.Uncertain {
		return m.handleUncertainResult(opType, cleanPath)
	}

	// If symlink chain exceeded depth limit, handle specially
	if result.Symlink != nil && result.Symlink.DepthLimitExceeded {
		return m.handleDepthLimitExceeded(opType, result)
	}

	// If symlink chain exists, emit entries for each hop plus the target
	if result.Symlink != nil {
		return m.handleSymlinkChain(opType, result)
	}

	// Skip logging reads of non-existent paths (noise reduction).
	// Processes routinely probe many paths that don't exist.
	if result.PathNotFound && opType == OperationRead {
		return nil
	}

	// No symlink - emit single entry for the path
	return m.logPathAccess(opType, cleanPath, result.Allowed, result.Rule, "path")
}

func (m *Monitor) handleRelativePath(opType OperationType, cleanPath string) error {
	entry := accesslog.Entry{
		Operation: accesslog.OperationType(opType),
		Target:    cleanPath,
		Result:    accesslog.ResultUnknown,
		Rule:      accesslog.RuleUnresolvedRelativePath,
	}
	if err := m.logger.Log(entry); err != nil {
		return fmt.Errorf("log relative path entry: %w", err)
	}
	return nil
}

func (m *Monitor) handleUncertainResult(opType OperationType, cleanPath string) error {
	entry := accesslog.Entry{
		Operation: accesslog.OperationType(opType),
		Target:    cleanPath,
		Result:    accesslog.ResultUnknown,
		Rule:      accesslog.RuleSymlinkTargetUnresolvable,
	}
	if err := m.logger.Log(entry); err != nil {
		return fmt.Errorf("log unresolvable symlink entry: %w", err)
	}
	return nil
}

func (m *Monitor) handleDepthLimitExceeded(opType OperationType, result fsrules.AccessResult) error {
	// Log each successful hop first
	for _, hop := range result.Symlink.Hops {
		if !hop.Allowed {
			break // This is the depth-limit hop
		}
		if err := m.logPathAccess(OperationRead, hop.Path, hop.Allowed, hop.Rule, "symlink hop"); err != nil {
			return err
		}
	}
	// Log the denied hop with the depth-limit reason
	lastHop := result.Symlink.Hops[len(result.Symlink.Hops)-1]
	entry := accesslog.Entry{
		Operation: accesslog.OperationType(opType),
		Target:    lastHop.Path,
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleSymlinkDepthExceeded,
	}
	if err := m.logger.Log(entry); err != nil {
		return fmt.Errorf("log depth limit entry: %w", err)
	}
	return nil
}

func (m *Monitor) handleSymlinkChain(opType OperationType, result fsrules.AccessResult) error {
	// Emit one READ entry per hop
	for _, hop := range result.Symlink.Hops {
		if err := m.logPathAccess(OperationRead, hop.Path, hop.Allowed, hop.Rule, "symlink hop"); err != nil {
			return err
		}

		// If hop was denied, stop - no target entry
		if !hop.Allowed {
			return nil
		}
	}

	// All hops were OK, emit target entry if we have a resolved path.
	// Skip reads of non-existent targets (noise reduction, same as non-symlink case).
	if result.Symlink.ResolvedPath != "" && (!result.PathNotFound || opType != OperationRead) {
		if err := m.logPathAccess(opType, result.Symlink.ResolvedPath, result.Allowed, result.Rule, "symlink target"); err != nil {
			return err
		}
	}

	return nil
}

// logPathAccess logs a path access by constructing an accesslog.Entry and passing it to the logger.
// The logger handles managed path filtering, deduplication, and formatting.
func (m *Monitor) logPathAccess(
	opType OperationType,
	path string,
	allowed bool,
	rule *fsrules.Rule,
	errorContext string,
) error {
	// Map monitor OperationType to accesslog OperationType
	var operation accesslog.OperationType
	if opType == OperationIgnored {
		return nil // Don't log ignored operations
	}
	// Monitor uses OperationRead/Write which match accesslog types
	operation = accesslog.OperationType(opType)

	result := accesslog.ResultOK
	if !allowed {
		result = accesslog.ResultDeny
	}

	ruleStr := accesslog.RuleNoMatch
	if rule != nil {
		ruleStr = rule.RawRule
	}

	entry := accesslog.Entry{
		Operation: operation,
		Target:    path,
		Result:    result,
		Rule:      ruleStr,
	}

	if err := m.logger.Log(entry); err != nil {
		return fmt.Errorf("log entry for %s: %w", errorContext, err)
	}

	return nil
}

func mapSyscallToOperation(syscall string, line string) OperationType {
	// Handle open/openat specially - operation depends on flags
	if syscall == "open" || syscall == "openat" {
		return classifyOpenOperation(line)
	}

	if op, ok := syscallOperationMap[syscall]; ok {
		return op
	}

	if ignoredSyscalls[syscall] {
		return OperationIgnored
	}

	// Unknown syscall - could indicate a new kernel syscall we should handle.
	panic("unknown syscall in strace output: " + syscall)
}

func normalizePath(path string) string {
	return filepath.Clean(path)
}

// syscallOperationMap maps syscalls to read or write operations.
//
//nolint:gochecknoglobals // package-private, used read-only
var syscallOperationMap = map[string]OperationType{
	// Read operations
	"stat": OperationRead, "lstat": OperationRead, "fstat": OperationRead,
	"fstatat": OperationRead, "newfstatat": OperationRead, "statx": OperationRead,
	"read": OperationRead, "readv": OperationRead, "pread": OperationRead,
	"pread64":    OperationRead,
	"readdir":    OperationRead,
	"getdents":   OperationRead,
	"getdents64": OperationRead,
	"readlink":   OperationRead, "readlinkat": OperationRead,
	"access": OperationRead, "faccessat": OperationRead, "faccessat2": OperationRead,
	"execve": OperationRead, "execveat": OperationRead,

	// Write operations
	"write": OperationWrite, "writev": OperationWrite, "pwrite": OperationWrite,
	"pwrite64":  OperationWrite,
	"unlink":    OperationWrite,
	"unlinkat":  OperationWrite,
	"rmdir":     OperationWrite,
	"mkdir":     OperationWrite,
	"mkdirat":   OperationWrite,
	"rename":    OperationWrite,
	"renameat":  OperationWrite,
	"renameat2": OperationWrite,
	"truncate":  OperationWrite, "ftruncate": OperationWrite,
	"chmod": OperationWrite, "fchmod": OperationWrite, "fchmodat": OperationWrite,
	"chown": OperationWrite, "fchown": OperationWrite, "lchown": OperationWrite,
	"fchownat": OperationWrite,
	"link":     OperationWrite, "linkat": OperationWrite, "symlink": OperationWrite,
	"symlinkat": OperationWrite,
	"creat":     OperationWrite,
}

// ignoredSyscalls lists syscalls from "trace=file" that we intentionally don't log.
// These don't represent meaningful filesystem access for our purposes.
//
//nolint:gochecknoglobals // package-private, used read-only
var ignoredSyscalls = map[string]bool{
	// Directory operations (don't access file contents)
	"chdir": true, "fchdir": true, "getcwd": true,
	// File descriptor operations (fd already opened, path not visible)
	"close": true, "dup": true, "dup2": true, "dup3": true, "fcntl": true,
	// Filesystem metadata (not file access)
	"statfs": true, "fstatfs": true, "ustat": true,
	// Mount/namespace operations (used by bwrap for sandbox setup, not user access)
	"mount": true, "umount": true, "umount2": true,
	"pivot_root": true, "chroot": true,
	"unshare": true, "setns": true, "clone": true, "clone3": true,
	"prctl": true,
	// Extended attributes (TODO: may want to track these)
	"getxattr": true, "lgetxattr": true, "fgetxattr": true,
	"setxattr": true, "lsetxattr": true, "fsetxattr": true,
	"listxattr": true, "llistxattr": true, "flistxattr": true,
	"removexattr": true, "lremovexattr": true, "fremovexattr": true,
	// Timestamps (minor metadata, already covered by chmod/chown)
	"utime": true, "utimes": true, "utimensat": true, "futimesat": true,
	// Watch/notify (doesn't access content)
	"inotify_add_watch": true, "fanotify_mark": true,
	// Handle-based (rare, path not directly visible)
	"name_to_handle_at": true, "open_by_handle_at": true,
}

func classifyOpenOperation(line string) OperationType {
	// Flags appear after the path argument. Find the path's closing quote
	// to avoid matching flag names that appear in filenames.
	// Strace format: open("/path", O_RDONLY) or openat(fd, "/path", O_CREAT|O_WRONLY)
	lastQuote := strings.LastIndex(line, "\"")
	if lastQuote == -1 {
		panic("classifyOpenOperation called with line lacking quotes: " + line)
	}

	flagsPart := line[lastQuote+1:]
	if strings.Contains(flagsPart, "O_WRONLY") || strings.Contains(flagsPart, "O_RDWR") || strings.Contains(flagsPart, "O_CREAT") {
		return OperationWrite
	}
	return OperationRead
}

type straceParser struct {
	syscallRegex    *regexp.Regexp
	atSyscallRegex  *regexp.Regexp
	fdFirstSyscalls map[string]bool
}

func newStraceParser() *straceParser {
	return &straceParser{
		// Matches: [pid] syscall("path" — captures syscall name and path
		syscallRegex: regexp.MustCompile(`^\d*\s*(\w+)\("([^"]+)"`),
		// Matches: [pid] syscall(fd<fdpath>, "path" — for *at() variants with fd as first arg
		// With strace -y, fd shows as: AT_FDCWD</cwd/path> or 3</proc/self>
		// Captures: 1=syscall, 2=fdpath (optional), 3=path
		atSyscallRegex: regexp.MustCompile(`^\d*\s*(\w+)\((?:AT_FDCWD|\d+)(?:<([^>]*)>)?,\s*"([^"]+)"`),
		fdFirstSyscalls: map[string]bool{
			"openat": true, "fstatat": true, "newfstatat": true, "faccessat": true,
			"faccessat2": true, "readlinkat": true, "mkdirat": true, "unlinkat": true,
			"renameat": true, "renameat2": true, "linkat": true, "symlinkat": true,
			"fchmodat": true, "fchownat": true, "execveat": true, "statx": true,
		},
	}
}

func (p *straceParser) parseLine(line string) (string, string, bool) {
	// Try *at/statx syscall format first (more specific)
	matches := p.atSyscallRegex.FindStringSubmatch(line)
	if len(matches) >= 4 && p.fdFirstSyscalls[matches[1]] {
		syscall := matches[1]
		fdPath := matches[2] // May be empty if strace didn't resolve fd
		path := matches[3]

		// Resolve relative paths using the fd path
		if fdPath != "" && !filepath.IsAbs(path) {
			path = filepath.Join(fdPath, path)
		}
		return syscall, path, true
	}

	// Try standard syscall format
	matches = p.syscallRegex.FindStringSubmatch(line)
	if len(matches) < 3 {
		return "", "", false
	}

	return matches[1], matches[2], true
}
