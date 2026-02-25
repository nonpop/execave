// Package accesslog provides in-memory access log storage with deduplication and filtering.
//
// The Logger stores access log entries for filesystem and network operations, handling:
// - Deduplication (each unique operation+target+result logged once)
// - Infrastructure path filtering (/dev, /proc, /tmp) for filesystem entries
// - Entry retrieval and change notification for consumers
package accesslog

import (
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

// Logger stores access log entries in memory with deduplication and filtering.
// Logger is safe for concurrent use by multiple goroutines.
type Logger struct {
	mu          sync.Mutex
	entries     []Entry
	seen        map[accessKey]bool
	managed     []string
	subscribers map[chan struct{}]bool
}

// New creates a new Logger.
// managedPaths contains infrastructure paths (/dev, /proc, /tmp) that should not be logged.
func New(managedPaths []string) *Logger {
	return &Logger{
		mu:          sync.Mutex{},
		entries:     make([]Entry, 0),
		seen:        make(map[accessKey]bool),
		managed:     managedPaths,
		subscribers: make(map[chan struct{}]bool),
	}
}

// Log stores an access log entry if it passes all filters:
// - Not a managed/infrastructure path.
// - Not already logged (deduplication).
// After storing the entry, notifies all subscribers via non-blocking send.
func (l *Logger) Log(entry Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isManagedPath(entry.Target) {
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

	l.entries = append(l.entries, entry)
	l.notifySubscribers()
}

// Entries returns a copy of all logged entries.
func (l *Logger) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries := make([]Entry, len(l.entries))
	copy(entries, l.entries)
	return entries
}

// Subscribe registers a channel to receive notifications when new entries are logged.
// The channel receives a non-blocking signal on each new entry.
// Callers should use Entries() to retrieve the current entry snapshot.
// The returned channel should only be used for receiving.
func (l *Logger) Subscribe() chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := make(chan struct{}, 1)
	l.subscribers[ch] = true
	return ch
}

// Unsubscribe removes a previously registered subscriber channel.
func (l *Logger) Unsubscribe(ch chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.subscribers, ch)
}

// notifySubscribers sends a non-blocking notification to all subscribers.
// Must be called with l.mu held.
func (l *Logger) notifySubscribers() {
	for ch := range l.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
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
