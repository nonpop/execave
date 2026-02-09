package e2e_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestE2E_AccessLog_LogFormat_AllowedReadLogged tests that allowed reads are logged with OK.
func TestE2E_AccessLog_LogFormat_AllowedReadLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	result := env.runMonitored(t, rules, "cat", testFile)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "OK", "fs:ro:"+env.TmpDir)
}

// TestE2E_AccessLog_LogFormat_DeniedWriteLogged tests that denied writes are logged with DENY.
func TestE2E_AccessLog_LogFormat_DeniedWriteLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Write will fail because sandbox enforces read-only
	result := env.runMonitored(t, rules, "sh", "-c", "echo test > "+testFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "WRITE", testFile, "DENY", "fs:ro:"+env.TmpDir)
}

// TestE2E_AccessLog_LogFormat_NoAccessRuleLogged tests that access to fs:none paths is logged with DENY.
func TestE2E_AccessLog_LogFormat_NoAccessRuleLogged(t *testing.T) {
	env := newMonitorTest(t)

	secretFile := filepath.Join(env.TmpDir, "secret.txt")
	createFile(t, secretFile, "secret")

	rules := append(systemPaths(), "fs:none:"+secretFile)

	// Read will fail because sandbox blocks fs:none paths
	result := env.runMonitored(t, rules, "cat", secretFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "READ", secretFile, "DENY", "fs:none:"+secretFile)
}

// TestE2E_AccessLog_LogFormat_NoMatchingRuleLogged tests that access without matching rule is logged.
func TestE2E_AccessLog_LogFormat_NoMatchingRuleLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	// System paths allowed but not our test file's directory
	result := env.runMonitored(t, systemPaths(), "cat", testFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "DENY", "no-matching-rule")
}

// TestE2E_AccessLog_LogFormat_UnresolvedRelativePathLogged is a placeholder for the
// "Unresolved relative path logged" spec scenario. I couldn't find a way to trigger it. Covered by unit test with synthetic data.
func TestE2E_AccessLog_LogFormat_UnresolvedRelativePathLogged(*testing.T) {}

// TestE2E_AccessLog_LogDeduplication_RepeatedReadsDeduplicated tests that repeated reads are deduplicated.
func TestE2E_AccessLog_LogDeduplication_RepeatedReadsDeduplicated(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Read the same file 3 times
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Specifically check that the test file appears only once with READ
	lines := 0
	for line := range strings.SplitSeq(logContent, "\n") {
		if strings.Contains(line, "READ") && strings.Contains(line, testFile) {
			lines++
		}
	}
	// Should be deduplicated to 1 entry
	assert.Equal(t, 1, lines)
}

// TestE2E_AccessLog_LogDeduplication_ReadAndWriteBothLogged tests that read and write to same file are both logged.
func TestE2E_AccessLog_LogDeduplication_ReadAndWriteBothLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "initial")

	rules := append(systemPaths(), "fs:rw:"+env.TmpDir)

	// Read then write to same file
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+testFile+" && echo 'more' >> "+testFile)
	assertExitCode(t, result, 0)

	// Should have both READ and WRITE entries
	assertLogLineContainsAll(t, env.LogPath, "READ", testFile)
	assertLogLineContainsAll(t, env.LogPath, "WRITE", testFile)
}

// TestE2E_AccessLog_LogDeduplication_RepeatedWritesDeduplicated tests that repeated writes are deduplicated.
func TestE2E_AccessLog_LogDeduplication_RepeatedWritesDeduplicated(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")

	rules := append(systemPaths(), "fs:rw:"+env.TmpDir)

	// Write to same file 3 times
	result := env.runMonitored(t, rules,
		"sh", "-c", "echo a > "+testFile+" && echo b >> "+testFile+" && echo c >> "+testFile)
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Should only have 1 WRITE entry for this file (deduplicated)
	lines := 0
	for line := range strings.SplitSeq(logContent, "\n") {
		if strings.Contains(line, "WRITE") && strings.Contains(line, testFile) {
			lines++
		}
	}
	// Should be deduplicated to 1 entry
	assert.Equal(t, 1, lines)
}

// TestE2E_AccessLog_InfrastructurePathFiltering_InfrastructurePathsNotLogged tests that infrastructure paths are not logged.
func TestE2E_AccessLog_InfrastructurePathFiltering_InfrastructurePathsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a command that accesses infrastructure paths
	// bash will access /proc, /dev/tty, etc.
	result := env.runMonitored(t, systemPaths(), "bash", "-c", "exit 0")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Infrastructure paths should NOT be in the log
	assert.NotContains(t, logContent, "/proc")
	assert.NotContains(t, logContent, "/dev")
	assert.NotContains(t, logContent, "newroot")
	assert.NotContains(t, logContent, "uid_map")

	// System paths should still be logged
	assert.Contains(t, logContent, "/usr/")
}

// TestE2E_AccessLog_InfrastructurePathFiltering_InfrastructureWritesNotLogged tests that writes to infrastructure paths are not logged.
func TestE2E_AccessLog_InfrastructurePathFiltering_InfrastructureWritesNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a command that writes to /dev/tty (or /dev/null as fallback)
	result := env.runMonitored(t, systemPaths(), "sh", "-c", "echo test > /dev/null")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Writes to /dev should NOT be in the log
	assert.NotContains(t, logContent, "/dev/")
}

// TestE2E_AccessLog_InfrastructurePathFiltering_FilesystemPathsStillLogged tests that only user-controlled filesystem paths are logged.
func TestE2E_AccessLog_InfrastructurePathFiltering_FilesystemPathsStillLogged(t *testing.T) {
	env := newMonitorTest(t)

	result := env.runMonitored(t, systemPaths(), "bash", "-c", "exit 0")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	assert.Contains(t, logContent, "/usr/")
}

// TestE2E_AccessLog_InfrastructurePathFiltering_SandboxSetupPathsNotLogged tests that sandbox setup paths are not logged.
func TestE2E_AccessLog_InfrastructurePathFiltering_SandboxSetupPathsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a simple command - sandbox setup will perform internal operations
	result := env.runMonitored(t, systemPaths(), "true")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Sandbox setup paths should NOT be in the log (no leading slash to catch
	// both absolute "/newroot" and relative "newroot" forms from bwrap)
	assert.NotContains(t, logContent, "newroot")
	assert.NotContains(t, logContent, "oldroot")
	assert.NotContains(t, logContent, "uid_map")
	assert.NotContains(t, logContent, "gid_map")
	assert.NotContains(t, logContent, "setgroups")
	assert.NotContains(t, logContent, "self/fd")
	assert.NotContains(t, logContent, "self/mountinfo")
}

// TestE2E_AccessLog_InfrastructurePathFiltering_NamespaceOperationsNotLogged tests that namespace operations are not logged.
func TestE2E_AccessLog_InfrastructurePathFiltering_NamespaceOperationsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a simple command - sandbox setup will perform internal operations
	result := env.runMonitored(t, systemPaths(), "true")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	assert.NotContains(t, logContent, "/ns/")
}
