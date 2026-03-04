package accesslog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func (s *syncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestLogger_LogEntry(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationRead,
		Target:    "/etc/passwd",
		Result:    ResultOK,
		Rule:      "fs:ro:/etc",
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
	assert.Contains(t, buf.String(), "/etc/passwd")
	assert.Contains(t, buf.String(), "OK")
	assert.Contains(t, buf.String(), "fs:ro:/etc")
}

func TestLogger_ConcurrentAccess(t *testing.T) {
	var buf syncBuffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	const numGoroutines = 10
	const entriesPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Each goroutine logs distinct entries
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range entriesPerGoroutine {
				entry := Entry{
					Operation: OperationRead,
					Target:    fmt.Sprintf("/tmp/file-%d-%d.txt", id, j),
					Result:    ResultOK,
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
			expectedPath := fmt.Sprintf("/tmp/file-%d-%d.txt", i, j)
			assert.Contains(t, buf.String(), expectedPath)
		}
	}
}

func TestLogger_Deduplication(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationRead,
		Target:    "/etc/passwd",
		Result:    ResultOK,
		Rule:      "fs:ro:/etc",
	}

	// Log the same entry twice
	logger.Log(entry)
	logger.Log(entry)

	// Should only appear once
	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestLogger_ReadAndWriteSeparate(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test"), 0o600)
	require.NoError(t, err)

	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	readEntry := Entry{
		Operation: OperationRead,
		Target:    testFile,
		Result:    ResultOK,
		Rule:      "fs:rw:" + tmpDir,
	}

	writeEntry := Entry{
		Operation: OperationWrite,
		Target:    testFile,
		Result:    ResultOK,
		Rule:      "fs:rw:" + tmpDir,
	}

	logger.Log(readEntry)
	logger.Log(writeEntry)

	// Both should be logged (different operations)
	assert.Equal(t, 2, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
	assert.Contains(t, buf.String(), "WRITE")
}

func TestLogger_ManagedPathFiltering(t *testing.T) {
	managedPaths := []string{"/dev", "/proc", "/tmp"}

	// Create a test file outside managed paths
	//nolint:usetesting // Need a path outside /tmp which t.TempDir() creates
	testDir, err := os.MkdirTemp(".", "accesslog-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	testFile := filepath.Join(absTestDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     string
		filtered bool
	}{
		{"proc file", "/proc/self/status", true},
		{"dev file", "/dev/null", true},
		{"tmp file", "/tmp/test.txt", true},
		{"existing file", testFile, false}, // Use real file that exists outside managed paths
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create new logger for each test to avoid deduplication issues
			var buf bytes.Buffer
			cfg := &Config{ManagedPaths: managedPaths, ShowAllowed: true}
			logger := New(&buf, cfg)

			entry := Entry{
				Operation: OperationRead,
				Target:    tt.path,
				Result:    ResultOK,
				Rule:      "fs:ro:/",
			}

			logger.Log(entry)

			if tt.filtered {
				assert.Empty(t, buf.String())
			} else {
				assert.Equal(t, 1, countLogLines(buf.String()))
			}
		})
	}
}

func TestLogger_NonExistentReadLogged(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	// File that doesn't exist — logger logs it regardless.
	// Non-existent path filtering is the resolver/monitor's responsibility.
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist.txt")

	readEntry := Entry{
		Operation: OperationRead,
		Target:    nonExistentPath,
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	logger.Log(readEntry)
	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
}

func TestLogger_ExistingFileLogged(t *testing.T) {
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "exists.txt")
	err := os.WriteFile(existingFile, []byte("test"), 0o600)
	require.NoError(t, err)

	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationRead,
		Target:    existingFile,
		Result:    ResultOK,
		Rule:      "fs:ro:" + tmpDir,
	}

	logger.Log(entry)
	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
}

func TestIsManagedPath(t *testing.T) {
	managedPaths := []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}
	logger := New(nil, &Config{ManagedPaths: managedPaths})

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Managed paths (infrastructure + bwrap internal)
		{"proc root", "/proc", true},
		{"proc file", "/proc/self/status", true},
		{"dev root", "/dev", true},
		{"dev file", "/dev/null", true},
		{"tmp root", "/tmp", true},
		{"tmp file", "/tmp/test.txt", true},
		{"newroot", "/newroot", true},
		{"newroot subdir", "/newroot/dev", true},
		{"oldroot", "/oldroot", true},
		{"oldroot subdir", "/oldroot/proc/self/fd/5", true},

		// Non-managed paths (user can configure rules)
		{"usr", "/usr", false},
		{"home", "/home", false},
		{"etc", "/etc", false},
		{"root", "/", false},
		{"usr bin", "/usr/bin/bash", false},
		{"home user", "/home/user/file.txt", false},
		{"uid_map in project", "/home/user/uid_map", false},
		{"ns dir in project", "/home/user/project/ns/config", false},
		{"self dir in project", "/home/user/self/fd", false},
		{"newroot dir in project", "/home/user/newroot", false},
		{"oldroot dir in project", "/home/user/oldroot", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logger.isManagedPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLogger_LogFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationWrite,
		Target:    "/home/user/project/file.txt",
		Result:    ResultDeny,
		Rule:      "fs:ro:/home/user/project",
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "WRITE")
	assert.Contains(t, buf.String(), "/home/user/project/file.txt")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), "fs:ro:/home/user/project")
}

func TestLogger_HTTPSEntry(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationHTTP,
		Target:    "api.example.com:443",
		Result:    ResultOK,
		Rule:      "net:http:api.example.com:443",
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "HTTP")
	assert.Contains(t, buf.String(), "api.example.com:443")
	assert.Contains(t, buf.String(), "OK")
	assert.Contains(t, buf.String(), "net:http:api.example.com:443")
}

func TestLogger_HTTPEntry(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationHTTP,
		Target:    "localhost:3000",
		Result:    ResultOK,
		Rule:      "net:http:localhost:3000",
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "localhost:3000")
}

func TestLogger_HTTPSDenied(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationHTTP,
		Target:    "malicious.example.com:443",
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "HTTP")
	assert.Contains(t, buf.String(), "malicious.example.com:443")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), RuleNoMatch)
}

func TestLogger_HTTPSDeduplication(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationHTTP,
		Target:    "api.example.com:443",
		Result:    ResultOK,
		Rule:      "net:http:api.example.com:443",
	}

	// Log the same entry three times
	for range 3 {
		logger.Log(entry)
	}

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestLogger_HTTPDeduplicatesAcrossCONNECTAndPlain(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	// CONNECT and plain HTTP to the same host:port now both log as OperationHTTP.
	// A second identical entry (same operation, target, result) deduplicates.
	entry := Entry{
		Operation: OperationHTTP,
		Target:    "example.com:443",
		Result:    ResultOK,
		Rule:      "net:http:example.com:443",
	}

	logger.Log(entry)
	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestLogger_NetworkEntriesNotFilteredByManagedPaths(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ManagedPaths: []string{"/dev", "/proc", "/tmp"}, ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationHTTP,
		Target:    "api.example.com:443",
		Result:    ResultOK,
		Rule:      "net:http:api.example.com:443",
	}

	logger.Log(entry)
	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestLogger_SyscallEntryLogged(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationSyscall,
		Target:    "bpf",
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "SYSCALL")
	assert.Contains(t, buf.String(), "bpf")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), RuleNoMatch)
}

func TestLogger_SyscallEntryDeduplicated(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationSyscall,
		Target:    "bpf",
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	logger.Log(entry)
	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestLogger_SyscallEntryNotFilteredByManagedPaths(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ManagedPaths: []string{"/dev", "/proc", "/tmp"}, ShowAllowed: true}
	logger := New(&buf, cfg)

	entry := Entry{
		Operation: OperationSyscall,
		Target:    "mount",
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestLogger_RuleReasonConstants(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name string
		rule string
	}{
		{"no match", RuleNoMatch},
		{"unresolved relative", RuleUnresolvedRelativePath},
		{"symlink unresolvable", RuleSymlinkTargetUnresolvable},
		{"depth exceeded", RuleSymlinkDepthExceeded},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create new logger and unique file for each test to avoid deduplication
			testFile := filepath.Join(tmpDir, fmt.Sprintf("test%d.txt", i))
			err := os.WriteFile(testFile, []byte("test"), 0o600)
			require.NoError(t, err)

			var buf bytes.Buffer
			cfg := &Config{ShowAllowed: true}
			logger := New(&buf, cfg)

			entry := Entry{
				Operation: OperationWrite, // Use WRITE so non-existent path filtering doesn't apply
				Target:    testFile,
				Result:    ResultUnknown,
				Rule:      tt.rule,
			}

			logger.Log(entry)
			assert.Equal(t, 1, countLogLines(buf.String()))
			assert.Contains(t, buf.String(), tt.rule)
		})
	}
}

func TestLogger_Close_BufferMode(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{ShowAllowed: true}
	logger := New(&buf, cfg)

	logger.Log(Entry{
		Operation: OperationRead,
		Target:    "/etc/hosts",
		Result:    ResultOK,
		Rule:      "fs:ro:/etc",
	})

	require.NoError(t, logger.Close())
	assert.Contains(t, buf.String(), "/etc/hosts")
}

func TestLogger_Close_WriteError(t *testing.T) {
	cfg := &Config{ShowAllowed: true}
	logger := New(&failWriter{}, cfg)

	logger.Log(Entry{
		Operation: OperationRead,
		Target:    "/etc/hosts",
		Result:    ResultOK,
		Rule:      "fs:ro:/etc",
	})

	assert.Error(t, logger.Close())
}

// failWriter is an io.Writer that always returns an error.
type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}
