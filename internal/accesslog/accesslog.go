// Package accesslog provides access logging with deduplication and filtering.
//
// The Logger stores access log entries for filesystem, network, and syscall operations, handling:
// - Deduplication (each unique operation+target+result logged once)
// - Infrastructure path filtering (/dev, /proc, /tmp) for filesystem entries
// - Optional real-time text output to a caller-provided writer
package accesslog

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nonpop/execave/internal/pathutil"
)

// OperationType classifies access operations.
type OperationType string

const (
	// OperationRead represents filesystem read operations (stat, open for read, etc).
	OperationRead OperationType = "READ"
	// OperationWrite represents filesystem write operations (write, unlink, mkdir, etc).
	OperationWrite OperationType = "WRITE"
	// OperationHTTP represents HTTP and CONNECT (tunneled) requests through the proxy.
	OperationHTTP OperationType = "HTTP"
	// OperationSyscall represents blocked syscall attempts intercepted by the seccomp filter.
	OperationSyscall OperationType = "SYSCALL"
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
	// ResultUnenforced indicates the access was observed but no sandbox enforcement was active.
	ResultUnenforced ResultType = "UNENFORCED"
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

// Entry represents a single access log entry.
type Entry struct {
	// Operation is the type of operation (READ, WRITE, HTTP, or SYSCALL).
	Operation OperationType
	// Target is the absolute path for filesystem ops, host:port for network ops, syscall name for SYSCALL ops.
	Target string
	// Result is the outcome of the access check (OK, DENY, UNKNOWN, or UNENFORCED).
	Result ResultType
	// Rule is the config rule that matched, or a reason code if no rule matched (e.g., no-matching-rule).
	Rule string
}

// Config configures the output for a Logger.
type Config struct {
	// ManagedPaths contains infrastructure paths (/dev, /proc, /tmp) that should not be logged.
	ManagedPaths []string
	// HomeDir is used for tilde-shortening paths in formatted output.
	HomeDir string
	// ConfigDir is used for config-relative shortening of paths in formatted output.
	ConfigDir string
	// ShowAllowed controls whether ResultOK entries are emitted.
	ShowAllowed bool
}

// accessKey uniquely identifies a log entry for deduplication.
type accessKey struct {
	operation OperationType
	target    string
	result    ResultType
}

// Logger writes access log entries to the configured output with deduplication and filtering.
// Logger is safe for concurrent use by multiple goroutines.
type Logger struct {
	mu       sync.Mutex
	seen     map[accessKey]bool
	out      io.Writer
	cfg      *Config
	writeErr error
}

// New creates a new Logger.
// out is the writer for text log output; nil means no output.
// cfg configures filtering and formatting; must be non-nil.
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

// Log writes an access log entry if it passes all filters:
// - Not a managed/infrastructure path.
// - Not already logged (deduplication).
// - Not blocked by ShowAllowed setting.
// If out is set, the entry is written to the configured output (if visible).
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

// Close returns the first write error encountered during logging, if any.
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
