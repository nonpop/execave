// Package accesslog provides deduplicating, filtered access logging for
// filesystem, network, and syscall operations observed by the monitor and proxy.
//
// All public methods on [Logger] are safe for concurrent use.
package accesslog

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nonpop/execave/internal/pathutil"
)

// OperationType classifies the kind of access being logged.
type OperationType string

const (
	// OperationRead represents filesystem read operations.
	OperationRead OperationType = "READ"
	// OperationWrite represents filesystem write operations.
	OperationWrite OperationType = "WRITE"
	// OperationHTTP represents HTTP/CONNECT requests through the proxy.
	OperationHTTP OperationType = "HTTP"
	// OperationSyscall represents syscall attempts intercepted by the seccomp filter.
	OperationSyscall OperationType = "SYSCALL"
)

// ResultType represents the outcome of an access check.
type ResultType string

const (
	// ResultOK indicates the access was allowed by rules.
	ResultOK ResultType = "OK"
	// ResultDeny indicates the access was denied by rules.
	ResultDeny ResultType = "DENY"
	// ResultUnknown indicates the result could not be determined.
	ResultUnknown ResultType = "UNKNOWN"
	// ResultUnenforced indicates the access was observed without sandbox enforcement.
	ResultUnenforced ResultType = "UNENFORCED"
)

// Rule reason constants for entries where no config rule matched.
const (
	// RuleUnresolvedRelativePath is used when a relative path could not be resolved.
	RuleUnresolvedRelativePath = "unresolved-relative-path"
	// RuleNoMatch is used when no matching rule was found.
	RuleNoMatch = "no-matching-rule"
	// RuleSymlinkTargetUnresolvable is used when a symlink chain enters a managed path.
	RuleSymlinkTargetUnresolvable = "symlink-target-unresolvable"
	// RuleSymlinkDepthExceeded is used when symlink resolution exceeded MAXSYMLINKS.
	RuleSymlinkDepthExceeded = "symlink-depth-limit-exceeded"
)

// Entry represents a single access log entry.
type Entry struct {
	Operation OperationType
	Target    string // Absolute path, host:port, or syscall name.
	Result    ResultType
	Rule      string // Matching config rule, or a Rule* reason constant.
}

// Config configures [Logger] filtering and formatting.
type Config struct {
	ManagedPaths []string // Infrastructure paths to suppress from output.
	HomeDir      string   // For tilde-shortening; empty disables.
	ConfigDir    string   // For config-relative shortening; empty disables.
	ShowAllowed  bool     // When false, [ResultOK] entries are suppressed.
}

// accessKey uniquely identifies a log entry for deduplication.
type accessKey struct {
	operation OperationType
	target    string
	result    ResultType
}

// Logger writes deduplicated, filtered access log entries to an [io.Writer].
type Logger struct {
	mu       sync.Mutex
	seen     map[accessKey]bool
	out      io.Writer
	cfg      *Config
	writeErr error
}

// New creates a new Logger that writes to out. out may be nil (no output).
// cfg must not be nil (panics otherwise).
func New(out io.Writer, cfg *Config) *Logger {
	if cfg == nil {
		panic("cfg must not be nil")
	}
	// All other Config fields have valid zero values: empty HomeDir/ConfigDir means
	// no path shortening, empty ManagedPaths means no infrastructure filtering,
	// and ShowAllowed is a plain bool.
	return &Logger{
		seen: make(map[accessKey]bool),
		out:  out,
		cfg:  cfg,
	}
}

// Log writes entry to the output if it passes filtering and deduplication.
func (l *Logger) Log(entry Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.out == nil || l.writeErr != nil {
		return
	}

	if !l.isVisible(entry) {
		return
	}

	key := accessKey{
		operation: entry.Operation,
		target:    entry.Target,
		result:    entry.Result,
	}
	if l.seen[key] {
		return
	}
	l.seen[key] = true

	line := l.formatEntry(entry) + "\n"
	if _, err := fmt.Fprint(l.out, line); err != nil {
		l.writeErr = fmt.Errorf("write log entry: %w", err)
	}
}

// Close returns the first write error encountered during the Logger's lifetime.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writeErr
}

// isVisible reports whether entry should be emitted given the cfg filters.
func (l *Logger) isVisible(entry Entry) bool {
	// Unenforced entries are always visible: the user explicitly requested
	// observation mode, so everything accessed should be shown.
	if entry.Result == ResultUnenforced {
		return true
	}
	if (entry.Operation == OperationRead || entry.Operation == OperationWrite) && l.isManagedPath(entry.Target) {
		return false
	}
	if !l.cfg.ShowAllowed && entry.Result == ResultOK {
		return false
	}
	return true
}

// formatEntry returns a formatted log line.
// Format: %-10s %-7s  %s  (%s)
// Example: UNENFORCED READ     ~/.ssh/id_rsa  (no-matching-rule)
func (l *Logger) formatEntry(entry Entry) string {
	target := entry.Target
	if (entry.Operation == OperationRead || entry.Operation == OperationWrite) && filepath.IsAbs(target) {
		target = pathutil.ShortenPath(target, l.cfg.HomeDir, l.cfg.ConfigDir)
	}
	return fmt.Sprintf("%-10s %-7s  %s  (%s)", entry.Result, entry.Operation, target, entry.Rule)
}

func (l *Logger) isManagedPath(path string) bool {
	cleanPath := filepath.Clean(path)

	for _, dir := range l.cfg.ManagedPaths {
		if cleanPath == dir || strings.HasPrefix(cleanPath, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
