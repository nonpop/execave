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

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/rules"
	"github.com/nonpop/execave/internal/sandbox"
)

// Monitor wraps command execution with strace to log filesystem access.
type Monitor struct {
	logPath   string
	resolver  *rules.Resolver
	seen      map[accessKey]bool
	bwrapArgs []string // strace wraps bwrap
}

type accessKey struct {
	operation OperationType
	path      string
	result    ResultType
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

// ResultType represents the outcome of an access check.
type ResultType string

const (
	// ResultOK indicates the access was allowed by rules.
	ResultOK ResultType = "OK"
	// ResultDeny indicates the access was denied by rules.
	ResultDeny ResultType = "DENY"
	// ResultUnknown indicates the result could not be determined (e.g., unresolved relative path).
	ResultUnknown ResultType = "UNKNOWN"
)

const (
	// RuleUnresolvedRelativePath is used when a relative path could not be resolved.
	RuleUnresolvedRelativePath = "unresolved-relative-path"
	// RuleNoMatch is used when no matching rule was found for a path.
	RuleNoMatch = "no-matching-rule"
	// RuleSymlinkTargetUnresolvable is used when a symlink chain enters a managed path
	// where host-side resolution is unreliable (e.g., sandbox tmpfs).
	RuleSymlinkTargetUnresolvable = "symlink-target-unresolvable"
	// RuleSymlinkDepthExceeded is used when the symlink resolution chain exceeded
	// the maximum depth (MAXSYMLINKS).
	RuleSymlinkDepthExceeded = "symlink-depth-limit-exceeded"
)

// New creates a new Monitor.
// bwrapArgs configures sandbox integration. If empty, strace traces the command directly.
func New(logPath string, resolver *rules.Resolver, bwrapArgs []string) *Monitor {
	return &Monitor{
		logPath:   logPath,
		resolver:  resolver,
		seen:      make(map[accessKey]bool),
		bwrapArgs: bwrapArgs,
	}
}

// Run executes a command with strace monitoring.
func (m *Monitor) Run(ctx context.Context, command []string) (int, error) {
	if _, err := exec.LookPath("strace"); err != nil {
		return 1, fmt.Errorf("strace not found in PATH: %w", err)
	}

	tmpPath, cleanup, err := createStraceOutputFile()
	if err != nil {
		return 1, err
	}
	defer cleanup()

	straceArgs := m.buildStraceArgs(tmpPath, command)
	exitCode, err := executeStrace(ctx, straceArgs)
	if err != nil {
		return exitCode, err
	}

	if err := m.processStraceResults(tmpPath); err != nil {
		return exitCode, err
	}

	return exitCode, nil
}

func (m *Monitor) buildStraceArgs(tmpPath string, command []string) []string {
	straceArgs := []string{
		"-f",               // Follow forks
		"-y",               // Print paths for file descriptors
		"-e", "trace=file", // Only file operations
		"-s", "0", // Don't capture string arguments
		"-o", tmpPath, // Output to temp file
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

func (m *Monitor) processStraceResults(tmpPath string) error {
	straceFile, err := os.Open(tmpPath) // #nosec G304 -- tmpPath is temp file created by caller
	if err != nil {
		return fmt.Errorf("open strace output %s: %w", tmpPath, err)
	}
	defer func() { _ = straceFile.Close() }()

	logFile, err := os.Create(m.logPath)
	if err != nil {
		return fmt.Errorf("create log file %s: %w", m.logPath, err)
	}
	defer func() { _ = logFile.Close() }()

	if err := m.processStraceOutput(straceFile, logFile); err != nil {
		return fmt.Errorf("process strace output: %w", err)
	}

	return nil
}

// processStraceOutput parses strace output and writes access log entries.
func (m *Monitor) processStraceOutput(output io.Reader, logFile *os.File) error {
	scanner := bufio.NewScanner(output)
	writer := bufio.NewWriter(logFile)
	defer func() {
		if err := writer.Flush(); err != nil {
			// Log flush error but don't override scanner error
			fmt.Fprintf(os.Stderr, "execave: failed to flush log writer: %v\n", err)
		}
	}()

	parser := newStraceParser()

	// When bwrap is used, strace captures bwrap's sandbox setup (namespace,
	// mount, pivot_root) before the user command starts. The strace output
	// contains at least two execve calls: bwrap's own (first) and the user
	// command (second). Skip all lines until the second execve.
	inSetup := len(m.bwrapArgs) > 0
	const expectedExecves = 2
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

		if err := m.processAccessEntry(writer, syscall, path, line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan strace output: %w", err)
	}
	return nil
}

func (m *Monitor) processAccessEntry(writer *bufio.Writer, syscall, path, line string) error {
	opType := mapSyscallToOperation(syscall, line)
	if opType == OperationIgnored {
		return nil
	}

	cleanPath := normalizePath(path)

	// Handle relative paths specially - we can't resolve them without cwd tracking,
	// but log them so the user knows something was accessed.
	if !filepath.IsAbs(cleanPath) {
		return m.handleRelativePath(writer, opType, cleanPath)
	}

	operation := rules.OperationRead
	if opType == OperationWrite {
		operation = rules.OperationWrite
	}

	result := m.resolver.CheckAccess(cleanPath, operation)

	// If symlink chain is unresolvable (entered managed path), log as UNKNOWN
	if result.Uncertain {
		return m.handleUncertainResult(writer, opType, cleanPath)
	}

	// If symlink chain exceeded depth limit, handle specially
	if result.Symlink != nil && result.Symlink.DepthLimitExceeded {
		return m.handleDepthLimitExceeded(writer, opType, result)
	}

	// If symlink chain exists, emit entries for each hop plus the target
	if result.Symlink != nil {
		return m.handleSymlinkChain(writer, opType, result)
	}

	// No symlink - emit single entry for the path
	return m.logPathAccess(writer, opType, cleanPath, result.Allowed, result.Rule, "path")
}

func (m *Monitor) handleRelativePath(writer *bufio.Writer, opType OperationType, cleanPath string) error {
	if m.alreadyLogged(opType, cleanPath, ResultUnknown) {
		return nil
	}
	if err := writeLogEntry(writer, opType, cleanPath, ResultUnknown, RuleUnresolvedRelativePath); err != nil {
		return fmt.Errorf("write log entry: %w", err)
	}
	return nil
}

func (m *Monitor) handleUncertainResult(writer *bufio.Writer, opType OperationType, cleanPath string) error {
	if m.alreadyLogged(opType, cleanPath, ResultUnknown) {
		return nil
	}
	if err := writeLogEntry(writer, opType, cleanPath, ResultUnknown, RuleSymlinkTargetUnresolvable); err != nil {
		return fmt.Errorf("write log entry for unresolvable symlink: %w", err)
	}
	return nil
}

func (m *Monitor) handleDepthLimitExceeded(writer *bufio.Writer, opType OperationType, result rules.AccessResult) error {
	// Log each successful hop first
	for _, hop := range result.Symlink.Hops {
		if !hop.Allowed {
			break // This is the depth-limit hop
		}
		if err := m.logPathAccess(writer, OperationRead, hop.Path, hop.Allowed, hop.Rule, "symlink hop"); err != nil {
			return err
		}
	}
	// Log the denied hop with the depth-limit reason
	lastHop := result.Symlink.Hops[len(result.Symlink.Hops)-1]
	if !m.alreadyLogged(opType, lastHop.Path, ResultDeny) {
		if err := writeLogEntry(writer, opType, lastHop.Path, ResultDeny, RuleSymlinkDepthExceeded); err != nil {
			return fmt.Errorf("write log entry for depth limit: %w", err)
		}
	}
	return nil
}

func (m *Monitor) handleSymlinkChain(writer *bufio.Writer, opType OperationType, result rules.AccessResult) error {
	// Emit one READ entry per hop
	for _, hop := range result.Symlink.Hops {
		if err := m.logPathAccess(writer, OperationRead, hop.Path, hop.Allowed, hop.Rule, "symlink hop"); err != nil {
			return err
		}

		// If hop was denied, stop - no target entry
		if !hop.Allowed {
			return nil
		}
	}

	// All hops were OK, emit target entry if we have a resolved path
	if result.Symlink.ResolvedPath != "" {
		if err := m.logPathAccess(writer, opType, result.Symlink.ResolvedPath, result.Allowed, result.Rule, "symlink target"); err != nil {
			return err
		}
	}

	return nil
}

func (m *Monitor) alreadyLogged(opType OperationType, path string, result ResultType) bool {
	key := accessKey{operation: opType, path: path, result: result}
	if m.seen[key] {
		return true
	}
	m.seen[key] = true
	return false
}

// logPathAccess writes a log entry for a path access if it isn't managed and hasn't been logged
// yet. Returns nil if the entry was logged or skipped (managed/duplicate), or an error if writing
// failed.
func (m *Monitor) logPathAccess(
	writer *bufio.Writer,
	opType OperationType,
	path string,
	allowed bool,
	rule *config.Rule,
	errorContext string,
) error {
	if isManagedPath(path) {
		return nil
	}

	result := ResultOK
	if !allowed {
		result = ResultDeny
	}

	if m.alreadyLogged(opType, path, result) {
		return nil
	}

	ruleStr := RuleNoMatch
	if rule != nil {
		ruleStr = rule.RawRule
	}

	if err := writeLogEntry(writer, opType, path, result, ruleStr); err != nil {
		return fmt.Errorf("write log entry for %s: %w", errorContext, err)
	}

	return nil
}

func createStraceOutputFile() (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "execave-strace-*.log")
	if err != nil {
		return "", nil, fmt.Errorf("create temp file for strace output: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return "", nil, fmt.Errorf("close temp file %s: %w", tmpPath, err)
	}

	cleanup := func() {
		if err := os.Remove(tmpPath); err != nil {
			fmt.Fprintf(os.Stderr, "execave: failed to remove temporary file %s: %v\n", tmpPath, err)
		}
	}

	return tmpPath, cleanup, nil
}

func executeStrace(ctx context.Context, straceArgs []string) (int, error) {
	cmd := exec.CommandContext(ctx, "strace", straceArgs...) // #nosec G204 -- args built from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		exitErr := new(exec.ExitError)
		if errors.As(err, &exitErr) {
			// Command ran but exited with non-zero code or signal
			ws, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok && ws.Signaled() {
				// Process was terminated by signal - return 128 + signal number
				// This matches shell convention (e.g., SIGINT = 2 → exit code 130)
				return 128 + int(ws.Signal()), nil //nolint: mnd // well-known code
			}
			return exitErr.ExitCode(), nil
		}
		// Failed to execute strace itself
		return 1, fmt.Errorf("execute strace: %w", err)
	}

	return 0, nil
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

// writeLogEntry writes a log entry: <OP> <PATH> <RESULT> <RULE>.
func writeLogEntry(writer io.Writer, opType OperationType, path string, result ResultType, rule string) error {
	logEntry := fmt.Sprintf("%-5s %-50s %-4s  %s", opType, path, result, rule)
	_, err := fmt.Fprintln(writer, logEntry)
	return err //nolint:wrapcheck // callers provide context
}

func isManagedPath(path string) bool {
	cleanPath := filepath.Clean(path)

	for _, dir := range sandbox.ManagedDirs {
		if cleanPath == dir || strings.HasPrefix(cleanPath, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
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
