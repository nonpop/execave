// Package monitor wraps commands with strace and processes strace output to
// log filesystem and syscall access decisions.
//
// [Prepare] builds the strace invocation. [Monitor.Run] reads strace output,
// resolves paths against [fsrules.Resolver], and logs entries via [accesslog.Logger].
// Run is intended for a dedicated goroutine; [Monitor] is not safe for
// concurrent calls to Run.
package monitor

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/syscallrules"
)

// Monitor processes strace output and logs access entries. Not safe for
// concurrent calls to [Monitor.Run].
type Monitor struct {
	logger          *accesslog.Logger
	fsResolver      *fsrules.Resolver
	syscallResolver *syscallrules.Resolver
	setupExecves    int
	unenforced      bool
}

// New creates a [Monitor]. syscallResolver may be nil to disable syscall tracing.
// setupExecves must not be negative (panics otherwise).
// When unenforced is true, all logged results are overridden to [accesslog.ResultUnenforced].
func New(
	logger *accesslog.Logger,
	fsResolver *fsrules.Resolver,
	syscallResolver *syscallrules.Resolver,
	setupExecves int,
	unenforced bool,
) *Monitor {
	if setupExecves < 0 {
		panic("execave bug: monitor created with negative setup exec count")
	}
	return &Monitor{
		logger:          logger,
		fsResolver:      fsResolver,
		syscallResolver: syscallResolver,
		setupExecves:    setupExecves,
		unenforced:      unenforced,
	}
}

// Run reads strace output from r and logs access entries until EOF.
func (p *Monitor) Run(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	cwdByPid := make(map[string]string)

	// When setup execves are configured, strace captures setup syscalls
	// (e.g., bwrap's namespace/mount/pivot_root) before the user command
	// starts. Skip setup lines and process the user command's execve.
	if p.setupExecves > 0 {
		p.skipSetup(scanner, cwdByPid)
	}

	for scanner.Scan() {
		line := scanner.Text()
		p.processStraceLine(cwdByPid, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan strace output: %w", err)
	}
	return nil
}

// skipSetup skips the setup initialization syscalls and processes
// any access entry and buffered lines that follow them.
func (p *Monitor) skipSetup(scanner *bufio.Scanner, cwdByPid map[string]string) {
	result, line, buffered, ok := findUserExecve(scanner, p.syscallResolver, p.setupExecves)
	if !ok {
		return
	}

	resolveCWD(cwdByPid, &result)
	p.processAccessEntry(result.syscall, result.path, line)
	for _, bl := range buffered {
		p.processStraceLine(cwdByPid, bl)
	}
}

// processStraceLine handles a single strace output line: parses it,
// updates cwd tracking, and logs access entries.
func (p *Monitor) processStraceLine(cwdByPid map[string]string, line string) {
	result, ok := parseLine(p.syscallResolver, line)
	if !ok {
		return
	}

	// Process exit clears the tracked cwd for the exiting pid, preventing
	// stale entries if the pid is reused within the same monitor run.
	if result.syscall == "exit" {
		delete(cwdByPid, result.pid)
		return
	}

	// Intercept monitored syscalls before filesystem processing.
	// These don't have meaningful paths and must not go through resolveCWD or processAccessEntry.
	if p.syscallResolver != nil {
		sr := p.syscallResolver.CheckAccess(result.syscall)
		if sr.Known && sr.Allowed {
			p.logEntry(accesslog.OperationSyscall, result.syscall, accesslog.ResultOK, *sr.Rule)
			return
		} else if sr.Known && !sr.Allowed {
			p.logEntry(accesslog.OperationSyscall, result.syscall, accesslog.ResultDeny, accesslog.RuleNoMatch)
			return
		}
	}

	if resolveCWD(cwdByPid, &result) {
		return
	}

	p.processAccessEntry(result.syscall, result.path, line)
}

func (p *Monitor) processAccessEntry(syscall, path, line string) {
	opType := mapSyscallToOperation(syscall, line)
	if opType == operationIgnored {
		return
	}

	cleanPath := filepath.Clean(path)

	// Handle relative paths specially - we can't resolve them without cwd tracking,
	// but log them so the user knows something was accessed.
	if !filepath.IsAbs(cleanPath) {
		p.logRelativePath(opType, cleanPath)
		return
	}

	operation := fsrules.OperationRead
	if opType == operationWrite {
		operation = fsrules.OperationWrite
	}

	result := p.fsResolver.CheckAccess(cleanPath, operation)

	// If symlink chain is unresolvable (entered managed path), log as UNKNOWN
	if result.Uncertain {
		p.logUncertainResult(opType, cleanPath)
		return
	}

	// If symlink chain exceeded depth limit, handle specially
	if result.Symlink != nil && result.Symlink.DepthLimitExceeded {
		p.logDepthLimitExceeded(opType, result)
		return
	}

	// If symlink chain exists, emit entries for each hop plus the target
	if result.Symlink != nil {
		p.logSymlinkChain(opType, result)
		return
	}

	// Skip logging reads of non-existent paths (noise reduction).
	// Processes routinely probe many paths that don't exist.
	if result.PathNotFound && opType == operationRead {
		return
	}

	// No symlink - emit single entry for the path
	p.logPathAccess(opType, cleanPath, result.Allowed, result.Rule)
}

// logPathAccess logs a path access by constructing an accesslog.Entry and passing it to the logger.
// The logger handles managed path filtering, deduplication, and formatting.
func (p *Monitor) logPathAccess(opType operationType, path string, allowed bool, rule *string) {
	if opType == operationIgnored {
		return // Don't log ignored operations
	}
	result := accesslog.ResultOK
	if !allowed {
		result = accesslog.ResultDeny
	}
	ruleStr := accesslog.RuleNoMatch
	if rule != nil {
		ruleStr = *rule
	}
	p.logEntry(toAccesslogOperation(opType), path, result, ruleStr)
}

func (p *Monitor) logRelativePath(opType operationType, cleanPath string) {
	p.logEntry(toAccesslogOperation(opType), cleanPath, accesslog.ResultUnknown, accesslog.RuleUnresolvedRelativePath)
}

func (p *Monitor) logUncertainResult(opType operationType, cleanPath string) {
	p.logEntry(toAccesslogOperation(opType), cleanPath, accesslog.ResultUnknown, accesslog.RuleSymlinkTargetUnresolvable)
}

func (p *Monitor) logDepthLimitExceeded(opType operationType, result fsrules.AccessResult) {
	// Log each successful hop first
	for _, hop := range result.Symlink.Hops {
		if !hop.Allowed {
			break // This is the depth-limit hop
		}
		p.logPathAccess(operationRead, hop.Path, hop.Allowed, hop.Rule)
	}
	// Log the denied hop with the depth-limit reason
	lastHop := result.Symlink.Hops[len(result.Symlink.Hops)-1]
	p.logEntry(toAccesslogOperation(opType), lastHop.Path, accesslog.ResultDeny, accesslog.RuleSymlinkDepthExceeded)
}

func (p *Monitor) logSymlinkChain(opType operationType, result fsrules.AccessResult) {
	// Emit one READ entry per hop
	for _, hop := range result.Symlink.Hops {
		p.logPathAccess(operationRead, hop.Path, hop.Allowed, hop.Rule)

		// If hop was denied, stop - no target entry
		if !hop.Allowed {
			return
		}
	}

	// All hops were OK, emit target entry if we have a resolved path.
	// Skip reads of non-existent targets (noise reduction, same as non-symlink case).
	if result.Symlink.ResolvedPath != "" && (!result.PathNotFound || opType != operationRead) {
		p.logPathAccess(opType, result.Symlink.ResolvedPath, result.Allowed, result.Rule)
	}
}

// logEntry logs an access entry, overriding the result to ResultUnenforced when unenforced mode is active.
func (p *Monitor) logEntry(op accesslog.OperationType, target string, result accesslog.ResultType, rule string) {
	if p.unenforced {
		result = accesslog.ResultUnenforced
	}
	p.logger.Log(accesslog.Entry{
		Operation: op,
		Target:    target,
		Result:    result,
		Rule:      rule,
	})
}

// findUserExecve advances the scanner past setup lines (e.g., bwrap sandbox initialization).
// The strace output contains execve calls for setup phases before the user command.
// Returns the parse result and raw line of the user command's execve.
//
// On EOF before expectedExecves, returns the last execve seen if at least 2
// execves were found (past the first setup exec). This handles cases where
// a setup process crashes before the full chain completes — the last
// execve is still processed so its access gets logged. The buffered slice
// contains raw strace lines consumed after the last execve during the scan;
// the caller must replay them. In the normal case (all expected execves found)
// buffered is nil.
func findUserExecve(scanner *bufio.Scanner, resolver *syscallrules.Resolver, expectedExecves int) (straceParseResult, string, []string, bool) {
	seenExecves := 0
	var lastResult straceParseResult
	var lastLine string
	var afterLastExecve []string
	for scanner.Scan() {
		line := scanner.Text()
		result, ok := parseLine(resolver, line)
		if !ok {
			if seenExecves > 0 {
				afterLastExecve = append(afterLastExecve, line)
			}
			continue
		}
		if result.syscall == "execve" || result.syscall == "execveat" {
			seenExecves++
			lastResult = result
			lastLine = line
			afterLastExecve = nil // reset: only keep lines after the latest execve
		} else if seenExecves > 0 {
			afterLastExecve = append(afterLastExecve, line)
		}
		if seenExecves >= expectedExecves {
			return result, line, nil, true
		}
	}
	// EOF before expected execves: return last execve if we got past the first setup exec.
	// seenExecves >= 2 means the setup exec'd something (tunnel or user command)
	// that is worth processing even though the full chain didn't complete.
	if seenExecves >= 2 { //nolint:mnd // 2 = past the first setup execve
		return lastResult, lastLine, afterLastExecve, true
	}
	return straceParseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, "", nil, false
}

// resolveCWD tracks per-process working directories and resolves relative paths.
// It updates cwdByPid from cwdHint, chdir, and fchdir changes, and resolves
// relative result.path using the tracked cwd.
// Returns true if the syscall was a chdir variant (caller should skip to next line).
func resolveCWD(cwdByPid map[string]string, result *straceParseResult) bool {
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

// toAccesslogOperation converts a monitor operationType to an accesslog operationType.
// opType must be operationRead or operationWrite; any other value panics.
func toAccesslogOperation(opType operationType) accesslog.OperationType {
	switch opType {
	case operationRead:
		return accesslog.OperationRead
	case operationWrite:
		return accesslog.OperationWrite
	default:
		panic(fmt.Sprintf("execave bug: unhandled filesystem operation type %q", opType))
	}
}
