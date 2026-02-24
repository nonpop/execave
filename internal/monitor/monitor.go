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
	resolver       *fsrules.AccessResolver
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
func New(logger *accesslog.Logger, resolver *fsrules.AccessResolver, bwrapArgs []string, hasNetworkPath bool) *Monitor {
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

	// Close the read end to unblock the processing goroutine. When strace is
	// killed (context cancellation), descendant processes (bwrap, sandboxed
	// command) may briefly hold the pipe write end open — they inherit fd 3
	// from strace but never use it. Without this close, the processing
	// goroutine blocks on read waiting for EOF that won't come until all
	// descendants die, which delays all post-exit cleanup (terminal
	// restoration, screen clearing, etc.).
	// In the normal exit case this is harmless: strace has already closed its
	// write end and the goroutine has already reached EOF or is about to.
	_ = straceR.Close()

	exitCode, exitErr := extractExitCode(err)
	if exitErr != nil {
		return exitCode, exitErr
	}

	// Wait for processing goroutine to finish
	processingErr := <-processingErrCh
	if processingErr != nil && ctx.Err() == nil {
		// Ignore pipe read errors caused by the forced close above (line 105).
		// When strace exits normally, we close straceR to unblock descendants
		// that inherited fd 3. This can race with the goroutine's read, causing
		// os.ErrClosed. This is benign and expected in normal exit scenarios.
		if !errors.Is(processingErr, os.ErrClosed) {
			return exitCode, fmt.Errorf("process strace output: %w", processingErr)
		}
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
		"-f",                      // Follow forks
		"-y",                      // Print paths for file descriptors
		"-e", "trace=file,fchdir", // Only file operations (fchdir is fd-based so not in 'file' group)
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
	cwdByPid := make(map[string]string)

	// When bwrap is used, strace captures bwrap's sandbox setup (namespace,
	// mount, pivot_root) before the user command starts. Skip setup lines
	// and process the user command's execve (the final setup execve).
	if len(m.bwrapArgs) > 0 {
		expectedExecves := 2
		if m.hasNetworkPath {
			expectedExecves = 3
		}
		result, line, ok := skipBwrapSetup(scanner, parser, expectedExecves)
		if ok {
			resolveCWD(cwdByPid, &result)
			if err := m.processAccessEntry(result.syscall, result.path, line); err != nil {
				return err
			}
		}
	}

	for scanner.Scan() {
		line := scanner.Text()

		if err := m.processStraceLine(parser, cwdByPid, line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan strace output: %w", err)
	}
	return nil
}

// processStraceLine handles a single strace output line: parses it,
// updates cwd tracking, and logs access entries.
func (m *Monitor) processStraceLine(parser *straceParser, cwdByPid map[string]string, line string) error {
	result, ok := parser.parseLine(line)
	if !ok {
		return nil
	}

	// Process exit clears the tracked cwd for the exiting pid, preventing
	// stale entries if the pid is reused within the same monitor run.
	if result.syscall == "exit" {
		delete(cwdByPid, result.pid)
		return nil
	}

	if resolveCWD(cwdByPid, &result) {
		return nil
	}

	return m.processAccessEntry(result.syscall, result.path, line)
}

// skipBwrapSetup advances the scanner past bwrap's sandbox setup lines.
// The strace output contains execve calls for setup: bwrap's own (first),
// optionally the tunnel (second when net rules present), and the user command
// (last). Returns the parse result and raw line of the user command's execve.
func skipBwrapSetup(scanner *bufio.Scanner, parser *straceParser, expectedExecves int) (parseResult, string, bool) {
	seenExecves := 0
	for scanner.Scan() {
		line := scanner.Text()
		result, ok := parser.parseLine(line)
		if !ok {
			continue
		}
		if result.syscall == "execve" || result.syscall == "execveat" {
			seenExecves++
		}
		if seenExecves >= expectedExecves {
			return result, line, true
		}
	}
	return parseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, "", false
}

// resolveCWD tracks per-process working directories and resolves relative paths.
// It updates cwdByPid from cwdHint, chdir, and fchdir changes, and resolves
// relative result.path using the tracked cwd.
// Returns true if the syscall was a chdir variant (caller should skip to next line).
func resolveCWD(cwdByPid map[string]string, result *parseResult) bool {
	if result.cwdHint != "" {
		cwdByPid[result.pid] = result.cwdHint
	}

	// Handle chdir: update tracked cwd (only on success)
	if result.syscall == "chdir" {
		if !result.failed {
			if filepath.IsAbs(result.path) {
				cwdByPid[result.pid] = result.path
			} else if existing, ok := cwdByPid[result.pid]; ok {
				cwdByPid[result.pid] = filepath.Join(existing, result.path)
			}
			// Relative chdir with no prior cwd: silently skip
		}
		return true
	}

	// Handle fchdir: fd-annotated path is the new cwd (only on success)
	if result.syscall == "fchdir" {
		if !result.failed {
			cwdByPid[result.pid] = result.path
		}
		return true
	}

	// Resolve bare-path relative paths using tracked cwd
	if !filepath.IsAbs(result.path) {
		if cwd, ok := cwdByPid[result.pid]; ok {
			result.path = filepath.Join(cwd, result.path)
		}
	}

	return false
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
	rule *fsrules.AccessRule,
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

// parseResult holds parsed data from a single strace line.
type parseResult struct {
	pid     string
	syscall string
	path    string
	cwdHint string // populated when AT_FDCWD has a <path> annotation
	failed  bool   // true when the syscall returned an error (= -1)
}

type straceParser struct {
	syscallRegex    *regexp.Regexp
	atSyscallRegex  *regexp.Regexp
	fchdirRegex     *regexp.Regexp
	exitEventRegex  *regexp.Regexp
	fdFirstSyscalls map[string]bool
}

func newStraceParser() *straceParser {
	return &straceParser{
		// Matches: [pid] syscall("path" — captures syscall name and path
		syscallRegex: regexp.MustCompile(`^\d*\s*(\w+)\("([^"]+)"`),
		// Matches: [pid] syscall(fd<fdpath>, "path" — for *at() variants with fd as first arg
		// With strace -y, fd shows as: AT_FDCWD</cwd/path> or 3</proc/self>
		// Captures: 1=syscall, 2=AT_FDCWD or fd number, 3=fdpath (optional), 4=path (may be empty)
		// Empty path occurs with AT_EMPTY_PATH flag (e.g., fstatat(fd, "", AT_EMPTY_PATH)).
		atSyscallRegex: regexp.MustCompile(`^\d*\s*(\w+)\((AT_FDCWD|\d+)(?:<([^>]*)>)?,\s*"([^"]*)"`),
		// Matches: [pid] fchdir(fd<path>) — captures the fd-annotated path
		// Captures: 1=path
		fchdirRegex: regexp.MustCompile(`^\d*\s*fchdir\(\d+<([^>]+)>\)`),
		// Matches process exit/kill events: "[pid] +++ exited with N +++"
		// Captures: 1=pid
		exitEventRegex: regexp.MustCompile(`^(\d+)\s*\+\+\+`),
		fdFirstSyscalls: map[string]bool{
			"openat": true, "fstatat": true, "newfstatat": true, "faccessat": true,
			"faccessat2": true, "readlinkat": true, "mkdirat": true, "unlinkat": true,
			"renameat": true, "renameat2": true, "linkat": true, "symlinkat": true,
			"fchmodat": true, "fchownat": true, "execveat": true, "statx": true,
		},
	}
}

// extractPid reads the pid prefix from a strace line.
// Strace -f file output uses "PID syscall(...)" format.
// Returns empty string for single-process traces (no pid prefix).
func (p *straceParser) extractPid(line string) string {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i > 0 {
		return line[:i]
	}
	return ""
}

// isFailed checks whether a strace line indicates a failed syscall.
// Strace format: "syscall(...) = -1 ERRNO (description)" for failures.
func (p *straceParser) isFailed(line string) bool {
	idx := strings.LastIndex(line, ") = ")
	if idx == -1 {
		return false
	}
	rest := line[idx+4:]
	return len(rest) > 0 && rest[0] == '-'
}

// parseAtSyscall interprets a matched *at/statx syscall line. It resolves
// the accessed path from the dirfd annotation and relative path argument.
func (p *straceParser) parseAtSyscall(pid string, matches []string, failed bool) (parseResult, bool) {
	syscall := matches[1]
	fdType := matches[2] // "AT_FDCWD" or numeric fd
	fdPath := matches[3] // May be empty if strace didn't resolve fd
	path := matches[4]

	var cwdHint string
	if fdType == "AT_FDCWD" && fdPath != "" {
		cwdHint = fdPath
	}

	// AT_EMPTY_PATH: empty path means the fd itself is the accessed target.
	// Only applies when a numeric dirfd is annotated with an absolute path.
	if path == "" {
		if fdType != "AT_FDCWD" && fdPath != "" && filepath.IsAbs(fdPath) {
			path = fdPath
		} else {
			return parseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, false
		}
	}

	// Resolve relative paths using the fd path
	if fdPath != "" && !filepath.IsAbs(path) {
		path = filepath.Join(fdPath, path)
	}
	return parseResult{pid: pid, syscall: syscall, path: path, cwdHint: cwdHint, failed: failed}, true
}

func (p *straceParser) parseLine(line string) (parseResult, bool) {
	pid := p.extractPid(line)
	failed := p.isFailed(line)

	// Try *at/statx syscall format first (more specific)
	matches := p.atSyscallRegex.FindStringSubmatch(line)
	if len(matches) >= 5 && p.fdFirstSyscalls[matches[1]] {
		if result, ok := p.parseAtSyscall(pid, matches, failed); ok {
			return result, true
		}
		return parseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, false
	}

	// Try standard syscall format
	matches = p.syscallRegex.FindStringSubmatch(line)
	if len(matches) >= 3 {
		return parseResult{pid: pid, syscall: matches[1], path: matches[2], cwdHint: "", failed: failed}, true
	}

	// Try fchdir: format is "PID fchdir(fd<path>)" — no quoted string arg
	matches = p.fchdirRegex.FindStringSubmatch(line)
	if matches != nil {
		return parseResult{pid: pid, syscall: "fchdir", path: matches[1], cwdHint: "", failed: failed}, true
	}

	// Detect process exit/kill events so the caller can clear stale cwd entries.
	// Strace format: "PID +++ exited with N +++" or "PID +++ killed by SIGNAME +++"
	matches = p.exitEventRegex.FindStringSubmatch(line)
	if matches != nil {
		return parseResult{pid: matches[1], syscall: "exit", path: "", cwdHint: "", failed: false}, true
	}

	return parseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, false
}
