package accesslog_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
)

// countLogLines returns the number of log entries written to s.
// Each entry is terminated by a newline, so this counts newlines.
func countLogLines(s string) int {
	return strings.Count(s, "\n")
}

// syncBuffer is a thread-safe bytes.Buffer for concurrent log tests.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p) //nolint:wrapcheck
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// failWriter is an io.Writer that always returns an error.
type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestLogger_ConcurrentAccess(t *testing.T) {
	var buf syncBuffer
	cfg := &accesslog.Config{ManagedPaths: nil, HomeDir: "", ConfigDir: "", ShowAllowed: true}
	logger := accesslog.New(&buf, cfg)

	const numGoroutines = 10
	const entriesPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Each goroutine logs distinct entries
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range entriesPerGoroutine {
				entry := accesslog.Entry{
					Operation: accesslog.OperationRead,
					Target:    fmt.Sprintf("/tmp/file-%d-%d.txt", id, j),
					Result:    accesslog.ResultOK,
					Rule:      "fs:ro:/tmp",
				}
				logger.Log(entry)
			}
		}(i)
	}

	wg.Wait()

	// Assert all distinct entries are present (no entries lost)
	expectedEntries := numGoroutines * entriesPerGoroutine
	assert.Equal(t, expectedEntries, countLogLines(buf.String()))

	// Verify each distinct entry appears exactly once
	for i := range numGoroutines {
		for j := range entriesPerGoroutine {
			assert.Contains(t, buf.String(), fmt.Sprintf("/tmp/file-%d-%d.txt", i, j))
		}
	}
}

// TestLogger_ManagedPathBoundaryFiltering verifies that the managed-path filter
// suppresses exactly the paths under configured managed directories and does not
// suppress paths that merely share a name prefix with a managed directory.
// This is security-relevant: a misconfigured boundary could leak infrastructure
// accesses or, worse, silently suppress user-file accesses.
func TestLogger_ManagedPathBoundaryFiltering(t *testing.T) {
	managedPaths := []string{"/newroot", "/oldroot", "/dev", "/proc", "/tmp"}

	tests := []struct {
		name     string
		path     string
		filtered bool
	}{
		// Managed paths — must be suppressed
		{"newroot root", "/newroot", true},
		{"newroot subdir", "/newroot/dev", true},
		{"oldroot subdir", "/oldroot/proc/self/fd/5", true},
		{"dev file", "/dev/null", true},
		{"proc file", "/proc/self/status", true},
		{"tmp file", "/tmp/test.txt", true},

		// Paths that share a prefix name but are not under a managed directory —
		// must not be suppressed (boundary check).
		{"newroot dir in home", "/home/user/newroot", false},
		{"oldroot dir in project", "/home/user/oldroot", false},
		{"non-managed file", "/home/user/file.txt", false},
		{"usr bin", "/usr/bin/bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := &accesslog.Config{ManagedPaths: managedPaths, HomeDir: "", ConfigDir: "", ShowAllowed: true}
			logger := accesslog.New(&buf, cfg)

			logger.Log(accesslog.Entry{
				Operation: accesslog.OperationRead,
				Target:    tt.path,
				Result:    accesslog.ResultOK,
				Rule:      "fs:ro:/",
			})

			if tt.filtered {
				assert.Empty(t, buf.String())
			} else {
				assert.Equal(t, 1, countLogLines(buf.String()))
			}
		})
	}
}

func TestLogger_Close_WriteError(t *testing.T) {
	cfg := &accesslog.Config{ManagedPaths: nil, HomeDir: "", ConfigDir: "", ShowAllowed: true}
	logger := accesslog.New(&failWriter{}, cfg)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/etc/hosts",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/etc",
	})

	assert.ErrorContains(t, logger.Close(), "write log entry")
}
