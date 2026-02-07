package e2e_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestE2E_AccessLog_LogFormat_AllowedHTTPSRequestLogged tests that the access log contains
// an HTTPS entry for an allowed CONNECT request.
func TestE2E_AccessLog_LogFormat_AllowedHTTPSRequestLogged(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPSServer(t, "LOG_HTTPS_OK")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	rules := append(systemPaths(),
		fmt.Sprintf("net:https:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"curl", "-sk", fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "LOG_HTTPS_OK")

	// Access log should contain HTTPS operation with OK result
	assertLogLineContainsAll(t, logPath, "HTTPS", host+":"+port, "OK")
}

// TestE2E_AccessLog_LogFormat_DeniedHTTPSRequestLogged tests that the access log contains
// an HTTPS DENY entry for a denied CONNECT request.
func TestE2E_AccessLog_LogFormat_DeniedHTTPSRequestLogged(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPSServer(t, "should not see this")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	// Dummy rule to trigger proxy, but doesn't match target
	rules := append(systemPaths(),
		"net:https:192.0.2.1:9999",
	)
	configPath := writeConfig(t, rules)

	_ = runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"curl", "-sk", "--max-time", "5", fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))

	// Access log should contain HTTPS operation with DENY result
	assertLogLineContainsAll(t, logPath, "HTTPS", host+":"+port, "DENY")
}

// TestE2E_AccessLog_LogFormat_AllowedHTTPRequestLogged tests that the access log contains
// an OK entry for an allowed HTTP request.
func TestE2E_AccessLog_LogFormat_AllowedHTTPRequestLogged(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPServer(t, "LOG_OK")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "LOG_OK")

	// Access log should contain HTTP operation with OK result
	assertLogLineContainsAll(t, logPath, "HTTP", host+":"+port, "OK")
}

// TestE2E_AccessLog_LogFormat_DeniedHTTPLogged tests that the access log contains
// a DENY entry for a denied HTTP request.
func TestE2E_AccessLog_LogFormat_DeniedHTTPLogged(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPServer(t, "should not see this")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	// Dummy rule to trigger proxy, but doesn't match target
	rules := append(systemPaths(),
		"net:https:192.0.2.1:9999",
	)
	configPath := writeConfig(t, rules)

	_ = runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	// Access log should contain HTTP operation with DENY result
	assertLogLineContainsAll(t, logPath, "HTTP", host+":"+port, "DENY")
}

// TestE2E_AccessLog_LogFormat_DeniedHTTPLoggedWithoutNetRules tests that when monitoring
// is enabled but no net rules are configured, HTTP requests are still logged as DENY.
func TestE2E_AccessLog_LogFormat_DeniedHTTPLoggedWithoutNetRules(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPServer(t, "should not see this")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	// No net rules — only system paths
	configPath := writeConfig(t, systemPaths())

	_ = runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	// Access log should contain HTTP operation with DENY result
	assertLogLineContainsAll(t, logPath, "HTTP", host+":"+port, "DENY", "no-matching-rule")
}

// TestE2E_AccessLog_LogFormat_UnresolvedRelativePathLogged is a placeholder for the
// "Unresolved relative path logged" spec scenario. Covered by unit test with synthetic data.
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

// TestE2E_AccessLog_LogDeduplication_RepeatedHTTPSRequestsDeduplicated tests that repeated HTTPS requests
// to the same target are deduplicated in the access log.
func TestE2E_AccessLog_LogDeduplication_RepeatedHTTPSRequestsDeduplicated(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPSServer(t, "DEDUP_OK")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	rules := append(systemPaths(),
		fmt.Sprintf("net:https:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	// Make two HTTPS requests to the same target
	target := fmt.Sprintf("https://%s/", net.JoinHostPort(host, port))
	result := runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"sh", "-c", fmt.Sprintf("curl -sk %s && curl -sk %s", target, target))

	assertExitCode(t, result, 0)

	data, err := os.ReadFile(logPath) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	logContent := string(data)

	// Should be deduplicated to 1 HTTPS OK entry for this target
	lines := 0
	for line := range strings.SplitSeq(logContent, "\n") {
		if strings.Contains(line, "HTTPS") && strings.Contains(line, host+":"+port) && strings.Contains(line, "OK") {
			lines++
		}
	}
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
