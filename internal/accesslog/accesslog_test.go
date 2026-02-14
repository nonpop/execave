package accesslog

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_LogEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationRead,
		Target:    "/etc/passwd",
		Result:    ResultOK,
		Rule:      "fs:ro:/etc",
	}

	err := logger.Log(entry)
	require.NoError(t, err)

	logStr := buf.String()
	assert.Contains(t, logStr, "READ")
	assert.Contains(t, logStr, "/etc/passwd")
	assert.Contains(t, logStr, "OK")
	assert.Contains(t, logStr, "fs:ro:/etc")
}

func TestLogger_ConcurrentAccess(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	const numGoroutines = 10
	const entriesPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errCh := make(chan error, numGoroutines*entriesPerGoroutine)

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
				if err := logger.Log(entry); err != nil {
					errCh <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	// Check for any errors from goroutines
	for err := range errCh {
		require.NoError(t, err)
	}

	// Assert all distinct entries are present (no entries lost)
	logStr := buf.String()
	lines := strings.Split(strings.TrimSpace(logStr), "\n")
	expectedEntries := numGoroutines * entriesPerGoroutine
	assert.Len(t, lines, expectedEntries)

	// Verify each distinct entry appears exactly once
	for i := range numGoroutines {
		for j := range entriesPerGoroutine {
			expectedPath := fmt.Sprintf("/tmp/file-%d-%d.txt", i, j)
			assert.Contains(t, logStr, expectedPath)
		}
	}
}

func TestLogger_Deduplication(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationRead,
		Target:    "/etc/passwd",
		Result:    ResultOK,
		Rule:      "fs:ro:/etc",
	}

	// Log the same entry twice
	err := logger.Log(entry)
	require.NoError(t, err)
	err = logger.Log(entry)
	require.NoError(t, err)

	// Should only appear once
	logStr := buf.String()
	lines := strings.Split(strings.TrimSpace(logStr), "\n")
	assert.Len(t, lines, 1)
}

func TestLogger_ReadAndWriteSeparate(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test"), 0o600)
	require.NoError(t, err)

	var buf bytes.Buffer
	logger := New(&buf, nil)

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

	err = logger.Log(readEntry)
	require.NoError(t, err)
	err = logger.Log(writeEntry)
	require.NoError(t, err)

	// Both should be logged (different operations)
	logStr := buf.String()
	lines := strings.Split(strings.TrimSpace(logStr), "\n")
	assert.Len(t, lines, 2)
	assert.Contains(t, logStr, "READ")
	assert.Contains(t, logStr, "WRITE")
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
			logger := New(&buf, managedPaths)

			entry := Entry{
				Operation: OperationRead,
				Target:    tt.path,
				Result:    ResultOK,
				Rule:      "fs:ro:/",
			}

			err := logger.Log(entry)
			require.NoError(t, err)

			if tt.filtered {
				assert.Empty(t, buf.String(), "expected path to be filtered")
			} else {
				assert.NotEmpty(t, buf.String(), "expected path to be logged")
			}
		})
	}
}

func TestLogger_NonExistentReadLogged(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	logger := New(&buf, nil)

	// File that doesn't exist — logger logs it regardless.
	// Non-existent path filtering is the resolver/monitor's responsibility.
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist.txt")

	readEntry := Entry{
		Operation: OperationRead,
		Target:    nonExistentPath,
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	err := logger.Log(readEntry)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String(), "read of non-existent file should be logged")
	assert.Contains(t, buf.String(), "READ")
}

func TestLogger_ExistingFileLogged(t *testing.T) {
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "exists.txt")
	err := os.WriteFile(existingFile, []byte("test"), 0o600)
	require.NoError(t, err)

	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationRead,
		Target:    existingFile,
		Result:    ResultOK,
		Rule:      "fs:ro:" + tmpDir,
	}

	err = logger.Log(entry)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	assert.Contains(t, buf.String(), "READ")
}

func TestIsManagedPath(t *testing.T) {
	managedPaths := []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}
	logger := New(nil, managedPaths)

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
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationWrite,
		Target:    "/home/user/project/file.txt",
		Result:    ResultDeny,
		Rule:      "fs:ro:/home/user/project",
	}

	err := logger.Log(entry)
	require.NoError(t, err)

	logStr := strings.TrimSpace(buf.String())
	parts := strings.Fields(logStr)

	// Format: <OP> <PATH> <RESULT> <RULE>
	require.GreaterOrEqual(t, len(parts), 4, "log entry should have at least 4 fields")
	assert.Equal(t, "WRITE", parts[0])
	assert.Equal(t, "/home/user/project/file.txt", parts[1])
	assert.Equal(t, "DENY", parts[2])
	assert.Equal(t, "fs:ro:/home/user/project", parts[3])
}

func TestLogger_HTTPSEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationHTTPS,
		Target:    "api.example.com:443",
		Result:    ResultOK,
		Rule:      "net:https:api.example.com:443",
	}

	err := logger.Log(entry)
	require.NoError(t, err)

	logStr := buf.String()
	assert.Contains(t, logStr, "HTTPS")
	assert.Contains(t, logStr, "api.example.com:443")
	assert.Contains(t, logStr, "OK")
	assert.Contains(t, logStr, "net:https:api.example.com:443")
}

func TestLogger_HTTPEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationHTTP,
		Target:    "localhost:3000",
		Result:    ResultOK,
		Rule:      "net:http:localhost:3000",
	}

	err := logger.Log(entry)
	require.NoError(t, err)

	logStr := buf.String()
	assert.Contains(t, logStr, "HTTP")
	assert.Contains(t, logStr, "localhost:3000")
}

func TestLogger_HTTPSDenied(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationHTTPS,
		Target:    "malicious.example.com:443",
		Result:    ResultDeny,
		Rule:      RuleNoMatch,
	}

	err := logger.Log(entry)
	require.NoError(t, err)

	logStr := buf.String()
	assert.Contains(t, logStr, "HTTPS")
	assert.Contains(t, logStr, "malicious.example.com:443")
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, "no-matching-rule")
}

func TestLogger_HTTPSDeduplication(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	entry := Entry{
		Operation: OperationHTTPS,
		Target:    "api.example.com:443",
		Result:    ResultOK,
		Rule:      "net:https:api.example.com:443",
	}

	// Log the same entry three times
	for range 3 {
		err := logger.Log(entry)
		require.NoError(t, err)
	}

	logStr := buf.String()
	lines := strings.Split(strings.TrimSpace(logStr), "\n")
	assert.Len(t, lines, 1)
}

func TestLogger_HTTPSAndHTTPSeparate(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, nil)

	httpsEntry := Entry{
		Operation: OperationHTTPS,
		Target:    "example.com:443",
		Result:    ResultOK,
		Rule:      "net:https:example.com:443",
	}

	httpEntry := Entry{
		Operation: OperationHTTP,
		Target:    "example.com:443",
		Result:    ResultOK,
		Rule:      "net:http:example.com:443",
	}

	err := logger.Log(httpsEntry)
	require.NoError(t, err)
	err = logger.Log(httpEntry)
	require.NoError(t, err)

	// Both should be logged (different operations)
	logStr := buf.String()
	lines := strings.Split(strings.TrimSpace(logStr), "\n")
	assert.Len(t, lines, 2)
}

func TestLogger_NetworkEntriesNotFilteredByManagedPaths(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, []string{"/dev", "/proc", "/tmp"})

	entry := Entry{
		Operation: OperationHTTPS,
		Target:    "api.example.com:443",
		Result:    ResultOK,
		Rule:      "net:https:api.example.com:443",
	}

	err := logger.Log(entry)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
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
			logger := New(&buf, nil)

			entry := Entry{
				Operation: OperationWrite, // Use WRITE so non-existent path filtering doesn't apply
				Target:    testFile,
				Result:    ResultUnknown,
				Rule:      tt.rule,
			}

			err = logger.Log(entry)
			require.NoError(t, err)
			assert.Contains(t, buf.String(), tt.rule)
		})
	}
}
