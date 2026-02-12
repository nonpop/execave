// Package accesslog provides access log writing with formatting, deduplication, and filtering.
//
// The Logger writes access log entries for filesystem and network operations, handling:
// - Entry formatting (<OP> <TARGET> <RESULT> <RULE>)
// - Deduplication (each unique operation+target+result logged once)
// - Infrastructure path filtering (/dev, /proc, /tmp) for filesystem entries
package accesslog

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
)

// OperationType classifies access operations.
type OperationType string

const (
	// OperationRead represents filesystem read operations (stat, open for read, etc).
	OperationRead OperationType = "READ"
	// OperationWrite represents filesystem write operations (write, unlink, mkdir, etc).
	OperationWrite OperationType = "WRITE"
	// OperationHTTPS represents HTTPS (CONNECT) requests through the proxy.
	OperationHTTPS OperationType = "HTTPS"
	// OperationHTTP represents plain HTTP requests through the proxy.
	OperationHTTP OperationType = "HTTP"
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

// Entry represents a single access log entry.
type Entry struct {
	// Operation is the type of operation (READ, WRITE, HTTPS, or HTTP).
	Operation OperationType
	// Target is the absolute path for filesystem ops, host:port for network ops.
	Target string
	// Result is the outcome of the access check (OK, DENY, or UNKNOWN).
	Result ResultType
	// Rule is the rule that matched or a reason string for why access was denied.
	Rule string
}

// accessKey uniquely identifies a log entry for deduplication.
type accessKey struct {
	operation OperationType
	target    string
	result    ResultType
}

// Logger writes access log entries with deduplication and filtering.
// Logger is safe for concurrent use by multiple goroutines.
type Logger struct {
	mu      sync.Mutex
	writer  io.Writer
	seen    map[accessKey]bool
	managed []string
}

// New creates a new Logger that writes to the given writer.
// managedPaths contains infrastructure paths (/dev, /proc, /tmp) that should not be logged.
func New(writer io.Writer, managedPaths []string) *Logger {
	return &Logger{
		mu:      sync.Mutex{},
		writer:  writer,
		seen:    make(map[accessKey]bool),
		managed: managedPaths,
	}
}

// Log writes an access log entry if it passes all filters:
// - Not a managed/infrastructure path.
// - Not already logged (deduplication).
func (l *Logger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isManagedPath(entry.Target) {
		return nil
	}

	key := accessKey{
		operation: entry.Operation,
		target:    entry.Target,
		result:    entry.Result,
	}
	if l.seen[key] {
		return nil
	}
	l.seen[key] = true

	return l.writeLogEntry(entry)
}

func (l *Logger) isManagedPath(path string) bool {
	cleanPath := filepath.Clean(path)

	for _, dir := range l.managed {
		if cleanPath == dir || strings.HasPrefix(cleanPath, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// writeLogEntry formats and writes a log entry: <OP> <PATH> <RESULT> <RULE>.
func (l *Logger) writeLogEntry(entry Entry) error {
	logLine := fmt.Sprintf("%-5s %-50s %-4s  %s", entry.Operation, entry.Target, entry.Result, entry.Rule)
	_, err := fmt.Fprintln(l.writer, logLine)
	return err //nolint:wrapcheck // callers provide context
}
