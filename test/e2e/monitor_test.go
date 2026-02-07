package e2e_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestE2E_Monitor_MonitorDisabledByDefault tests that monitoring is disabled by default.
func TestE2E_Monitor_MonitorDisabledByDefault(t *testing.T) {
	failIfNoBwrap(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	logPath := filepath.Join(workDir, "execave-access.log")

	result := runExecave(t, workDir, "--", "true")
	assertExitCode(t, result, 0)

	assertLogNotExists(t, logPath)
}

// TestE2E_Monitor_MonitorEnabled tests that --monitor enables monitoring and writes
// the access log to the default path (./execave-access.log).
func TestE2E_Monitor_MonitorEnabled(t *testing.T) {
	failIfNoStrace(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	// Default log path: ./execave-access.log relative to working directory
	logPath := filepath.Join(workDir, "execave-access.log")

	result := runExecave(t, workDir, "--monitor", "--", "true")
	assertExitCode(t, result, 0)

	assertLogExists(t, logPath)
}

// TestE2E_Monitor_CustomLogPath tests that --monitor=<path> creates a log at the specified path.
func TestE2E_Monitor_CustomLogPath(t *testing.T) {
	failIfNoStrace(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	customLogPath := filepath.Join(workDir, "custom-access.log")

	result := runExecave(t, workDir, "--monitor="+customLogPath, "--", "true")
	assertExitCode(t, result, 0)

	assertLogExists(t, customLogPath)
}

// TestE2E_Monitor_AllowedReadLogged tests that allowed reads are logged with OK.
func TestE2E_Monitor_AllowedReadLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	result := env.runMonitored(t, rules, "cat", testFile)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "OK", "fs:ro:"+env.TmpDir)
}

// TestE2E_Monitor_DeniedWriteLogged tests that denied writes are logged with DENY.
func TestE2E_Monitor_DeniedWriteLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Write will fail because sandbox enforces read-only
	result := env.runMonitored(t, rules, "sh", "-c", "echo test > "+testFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "WRITE", testFile, "DENY", "fs:ro:"+env.TmpDir)
}

// TestE2E_Monitor_NoAccessRuleLogged tests that access to fs:none paths is logged with DENY.
func TestE2E_Monitor_NoAccessRuleLogged(t *testing.T) {
	env := newMonitorTest(t)

	secretFile := filepath.Join(env.TmpDir, "secret.txt")
	createFile(t, secretFile, "secret")

	rules := append(systemPaths(), "fs:none:"+secretFile)

	// Read will fail because sandbox blocks fs:none paths
	result := env.runMonitored(t, rules, "cat", secretFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "READ", secretFile, "DENY", "fs:none:"+secretFile)
}

// TestE2E_Monitor_NoMatchingRuleLogged tests that access without matching rule is logged.
func TestE2E_Monitor_NoMatchingRuleLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	// System paths allowed but not our test file's directory
	result := env.runMonitored(t, systemPaths(), "cat", testFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "DENY", "no-matching-rule")
}

// TestE2E_Monitor_UnresolvedRelativePathLogged is a placeholder for the
// "Unresolved relative path logged" spec scenario. I couldn't find a way to trigger it. Covered by unit test with synthetic data.
func TestE2E_Monitor_UnresolvedRelativePathLogged(*testing.T) {}

// TestE2E_Monitor_QueryingFileMetadataLoggedAsRead tests that querying file metadata is logged as READ.
func TestE2E_Monitor_QueryingFileMetadataLoggedAsRead(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// stat queries file metadata without reading contents
	result := env.runMonitored(t, rules, "stat", testFile)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "OK", "fs:ro:"+env.TmpDir)
}

// TestE2E_Monitor_CreatingDirectoryLoggedAsWrite tests that creating a directory is logged as WRITE.
func TestE2E_Monitor_CreatingDirectoryLoggedAsWrite(t *testing.T) {
	env := newMonitorTest(t)

	newDir := filepath.Join(env.TmpDir, "newdir")

	rules := append(systemPaths(), "fs:rw:"+env.TmpDir)

	result := env.runMonitored(t, rules, "mkdir", newDir)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "WRITE", newDir, "OK", "fs:rw:"+env.TmpDir)
}

// TestE2E_Monitor_RepeatedReadsDeduplicated tests that repeated reads are deduplicated.
func TestE2E_Monitor_RepeatedReadsDeduplicated(t *testing.T) {
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

// TestE2E_Monitor_ReadAndWriteBothLogged tests that read and write to same file are both logged.
func TestE2E_Monitor_ReadAndWriteBothLogged(t *testing.T) {
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

// TestE2E_Monitor_RepeatedWritesDeduplicated tests that repeated writes are deduplicated.
func TestE2E_Monitor_RepeatedWritesDeduplicated(t *testing.T) {
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

// TestE2E_Monitor_InfrastructurePathsNotLogged tests that infrastructure paths are not logged.
func TestE2E_Monitor_InfrastructurePathsNotLogged(t *testing.T) {
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

// TestE2E_Monitor_InfrastructureWritesNotLogged tests that writes to infrastructure paths are not logged.
func TestE2E_Monitor_InfrastructureWritesNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a command that writes to /dev/tty (or /dev/null as fallback)
	result := env.runMonitored(t, systemPaths(), "sh", "-c", "echo test > /dev/null")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Writes to /dev should NOT be in the log
	assert.NotContains(t, logContent, "/dev/")
}

// TestE2E_Monitor_FilesystemPathsStillLogged tests that only user-controlled filesystem paths are logged.
func TestE2E_Monitor_FilesystemPathsStillLogged(t *testing.T) {
	env := newMonitorTest(t)

	result := env.runMonitored(t, systemPaths(), "bash", "-c", "exit 0")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	assert.Contains(t, logContent, "/usr/")
}

// TestE2E_Monitor_SandboxSetupPathsNotLogged tests that sandbox setup paths are not logged.
func TestE2E_Monitor_SandboxSetupPathsNotLogged(t *testing.T) {
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

// TestE2E_Monitor_NamespaceOperationsNotLogged tests that namespace operations are not logged.
func TestE2E_Monitor_NamespaceOperationsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a simple command - sandbox setup will perform internal operations
	result := env.runMonitored(t, systemPaths(), "true")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	assert.NotContains(t, logContent, "/ns/")
}

// TestE2E_Monitor_AccessLogWrittenAfterChildTerminatedBySIGINT tests that the access log
// is written even when the child process is terminated by SIGINT (ctrl-c).
func TestE2E_Monitor_AccessLogWrittenAfterChildTerminatedBySIGINT(t *testing.T) {
	env := newMonitorTest(t)

	// Start execave with --monitor and a long-running command
	// We'll send SIGINT to the process group after a short delay
	result := env.runMonitoredWithInterrupt(t, systemPaths(), "sleep", "60")

	// Exit code should be 130 (128 + SIGINT=2)
	assertExitCode(t, result, 130)

	// Access log should exist and contain entries
	assertLogExists(t, env.LogPath)

	// The log should have at least system path accesses
	logContent := env.readLog(t)
	assert.NotEmpty(t, logContent)
}
