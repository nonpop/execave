package monitor

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nonpop/execave/internal/syscallrules"
)

// straceParseResult holds parsed data from a single strace line.
type straceParseResult struct {
	pid     string
	syscall string
	path    string
	cwdHint string // populated when AT_FDCWD has a <path> annotation
	failed  bool   // true when the syscall returned an error (= -1)
}

var (
	// syscallRegex matches: [pid] syscall("path" — captures syscall name and path.
	syscallRegex = regexp.MustCompile(`^\d*\s*(\w+)\("([^"]+)"`)
	// atSyscallRegex matches: [pid] syscall(fd<fdpath>, "path" — for *at() variants with fd as first arg
	// With strace -y, fd shows as: AT_FDCWD</cwd/path> or 3</proc/self>
	// Captures: 1=syscall, 2=AT_FDCWD or fd number, 3=fdpath (optional), 4=path (may be empty)
	// Empty path occurs with AT_EMPTY_PATH flag (e.g., fstatat(fd, "", AT_EMPTY_PATH)).
	atSyscallRegex = regexp.MustCompile(`^\d*\s*(\w+)\((AT_FDCWD|\d+)(?:<([^>]*)>)?,\s*"([^"]*)"`)
	// fchdirRegex matches: [pid] fchdir(fd<path>) — captures the fd-annotated path
	// Captures: 1=path.
	fchdirRegex = regexp.MustCompile(`^\d*\s*fchdir\(\d+<([^>]+)>\)`)
	// exitEventRegex matches process exit/kill events: "[pid] +++ exited with N +++"
	// Captures: 1=pid.
	exitEventRegex = regexp.MustCompile(`^(\d+)\s*\+\+\+`)
	// fallbackRegex matches: [pid] syscall( — captures just the syscall name before "("
	// Tried last to match non-file syscalls (e.g., ptrace, bpf) that have no path arg.
	fallbackRegex = regexp.MustCompile(`^\d*\s*(\w+)\(`)

	fdFirstSyscalls = map[string]bool{ //nolint:gochecknoglobals // package-private, used read-only
		"openat": true, "fstatat": true, "newfstatat": true, "faccessat": true,
		"faccessat2": true, "readlinkat": true, "mkdirat": true, "unlinkat": true,
		"renameat": true, "renameat2": true, "linkat": true, "symlinkat": true,
		"fchmodat": true, "fchownat": true, "execveat": true, "statx": true,
	}
)

func parseLine(resolver *syscallrules.Resolver, line string) (straceParseResult, bool) {
	pid := extractPid(line)
	failed := isFailed(line)

	// Try *at/statx syscall format first (more specific)
	matches := atSyscallRegex.FindStringSubmatch(line)
	if len(matches) >= 5 && fdFirstSyscalls[matches[1]] {
		if result, ok := parseAtSyscall(pid, matches, failed); ok {
			return result, true
		}
		return straceParseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, false
	}

	// Try standard syscall format
	matches = syscallRegex.FindStringSubmatch(line)
	if len(matches) >= 3 {
		return straceParseResult{pid: pid, syscall: matches[1], path: matches[2], cwdHint: "", failed: failed}, true
	}

	// Try fchdir: format is "PID fchdir(fd<path>)" — no quoted string arg
	matches = fchdirRegex.FindStringSubmatch(line)
	if matches != nil {
		return straceParseResult{pid: pid, syscall: "fchdir", path: matches[1], cwdHint: "", failed: failed}, true
	}

	// Detect process exit/kill events so the caller can clear stale cwd entries.
	// Strace format: "PID +++ exited with N +++" or "PID +++ killed by SIGNAME +++"
	matches = exitEventRegex.FindStringSubmatch(line)
	if matches != nil {
		return straceParseResult{pid: matches[1], syscall: "exit", path: "", cwdHint: "", failed: false}, true
	}

	// Fallback: match bare syscall name for non-file syscalls (e.g., ptrace, bpf).
	// Only intercept if the name is a known monitored syscall.
	matches = fallbackRegex.FindStringSubmatch(line)
	if len(matches) >= 2 { //nolint:mnd // minimum regex group count
		name := matches[1]
		if resolver != nil && resolver.CheckAccess(name).Known {
			return straceParseResult{pid: pid, syscall: name, path: "", cwdHint: "", failed: failed}, true
		}
	}

	return straceParseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, false
}

// extractPid reads the pid prefix from a strace line.
// Strace -f file output uses "PID syscall(...)" format.
// Returns empty string for single-process traces (no pid prefix).
func extractPid(line string) string {
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
func isFailed(line string) bool {
	idx := strings.LastIndex(line, ") = ")
	if idx == -1 {
		return false
	}
	rest := line[idx+4:]
	return len(rest) > 0 && rest[0] == '-'
}

// parseAtSyscall interprets a matched *at/statx syscall line. It resolves
// the accessed path from the dirfd annotation and relative path argument.
func parseAtSyscall(pid string, matches []string, failed bool) (straceParseResult, bool) {
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
			return straceParseResult{pid: "", syscall: "", path: "", cwdHint: "", failed: false}, false
		}
	}

	// Resolve relative paths using the fd path
	if fdPath != "" && !filepath.IsAbs(path) {
		path = filepath.Join(fdPath, path)
	}
	return straceParseResult{pid: pid, syscall: syscall, path: path, cwdHint: cwdHint, failed: failed}, true
}
