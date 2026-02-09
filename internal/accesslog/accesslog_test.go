package accesslog_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_LogEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Path:      "/etc/passwd",
		Result:    accesslog.ResultOK,
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

func TestLogger_Deduplication(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Path:      "/etc/passwd",
		Result:    accesslog.ResultOK,
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
	logger := accesslog.New(&buf, nil)

	readEntry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Path:      testFile,
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:" + tmpDir,
	}

	writeEntry := accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Path:      testFile,
		Result:    accesslog.ResultOK,
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
			logger := accesslog.New(&buf, managedPaths)

			entry := accesslog.Entry{
				Operation: accesslog.OperationRead,
				Path:      tt.path,
				Result:    accesslog.ResultOK,
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
	logger := accesslog.New(&buf, nil)

	// File that doesn't exist — logger logs it regardless.
	// Non-existent path filtering is the resolver/monitor's responsibility.
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist.txt")

	readEntry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Path:      nonExistentPath,
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
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
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Path:      existingFile,
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:" + tmpDir,
	}

	err = logger.Log(entry)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	assert.Contains(t, buf.String(), "READ")
}

func TestIsManagedPath(t *testing.T) {
	managedPaths := []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}
	logger := accesslog.New(nil, managedPaths)

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
			result := logger.IsManagedPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLogger_LogFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Path:      "/home/user/project/file.txt",
		Result:    accesslog.ResultDeny,
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

func TestLogger_RuleReasonConstants(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name string
		rule string
	}{
		{"no match", accesslog.RuleNoMatch},
		{"unresolved relative", accesslog.RuleUnresolvedRelativePath},
		{"symlink unresolvable", accesslog.RuleSymlinkTargetUnresolvable},
		{"depth exceeded", accesslog.RuleSymlinkDepthExceeded},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create new logger and unique file for each test to avoid deduplication
			testFile := filepath.Join(tmpDir, fmt.Sprintf("test%d.txt", i))
			err := os.WriteFile(testFile, []byte("test"), 0o600)
			require.NoError(t, err)

			var buf bytes.Buffer
			logger := accesslog.New(&buf, nil)

			entry := accesslog.Entry{
				Operation: accesslog.OperationWrite, // Use WRITE so non-existent path filtering doesn't apply
				Path:      testFile,
				Result:    accesslog.ResultUnknown,
				Rule:      tt.rule,
			}

			err = logger.Log(entry)
			require.NoError(t, err)
			assert.Contains(t, buf.String(), tt.rule)
		})
	}
}
