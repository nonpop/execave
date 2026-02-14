package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_MonitoringAccess_MonitorFilesystemAccessWithDefaultLogPath tests that --monitor
// writes filesystem access entries to the default log path (./execave-access.log).
func TestE2E_MonitoringAccess_MonitorFilesystemAccessWithDefaultLogPath(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	workDir := testTempDir(t)
	dataDir := filepath.Join(workDir, "data")
	dataFile := filepath.Join(dataDir, "file.txt")
	createFile(t, dataFile, "test data")

	rules := append(systemPaths(), "fs:ro:"+dataDir)
	writeConfigInDir(t, workDir, rules)

	logPath := filepath.Join(workDir, "execave-access.log")

	result := runExecave(t, workDir, "--monitor", "--", "cat", dataFile)
	assertExitCode(t, result, 0)

	assertLogExists(t, logPath)
	assertLogLineContainsAll(t, logPath, "READ", dataFile)
}

// TestE2E_MonitoringAccess_MonitorFilesystemAccessWithCustomLogPath tests that
// --monitor=<path> writes the access log to the specified path.
func TestE2E_MonitoringAccess_MonitorFilesystemAccessWithCustomLogPath(t *testing.T) {
	env := newMonitorTest(t)

	dataFile := filepath.Join(env.TmpDir, "file.txt")
	createFile(t, dataFile, "test data")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	result := env.runMonitored(t, rules, "cat", dataFile)
	assertExitCode(t, result, 0)

	assertLogExists(t, env.LogPath)
	assertLogLineContainsAll(t, env.LogPath, "READ", dataFile)
}

// TestE2E_MonitoringAccess_MonitorNetworkAccess tests that monitoring with net rules
// captures HTTPS and HTTP entries in the access log.
func TestE2E_MonitoringAccess_MonitorNetworkAccess(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPSServer(t, "NET_MONITOR_OK")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	rules := append(systemPaths(),
		fmt.Sprintf("net:https:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--monitor="+logPath, "--",
		"curl", "-sk", fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, logPath, "HTTPS", host+":"+port, "OK")
}

// TestE2E_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently tests that monitoring
// captures both filesystem READ/WRITE entries and network HTTPS entries in a single log.
func TestE2E_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPSServer(t, "CONCURRENT_OK")

	tmpDir := testTempDir(t)
	dataFile := filepath.Join(tmpDir, "data.txt")
	createFile(t, dataFile, "fs data")
	logPath := filepath.Join(tmpDir, "access.log")

	rules := append(systemPaths(),
		"fs:ro:"+tmpDir,
		fmt.Sprintf("net:https:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--monitor="+logPath, "--",
		"sh", "-c", fmt.Sprintf("cat %s && curl -sk https://%s/", dataFile, net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)

	// Both filesystem and network entries in the same log
	assertLogLineContainsAll(t, logPath, "READ", dataFile, "OK")
	assertLogLineContainsAll(t, logPath, "HTTPS", host+":"+port, "OK")
}

// TestE2E_MonitoringAccess_RealTimeLogMonitoring tests that log entries are written
// during execution and visible to external readers (e.g., tail -f) before the command exits.
func TestE2E_MonitoringAccess_RealTimeLogMonitoring(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "data.txt")
	createFile(t, testFile, "test content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)
	configPath := writeConfig(t, rules)

	// Start a command that reads the file then sleeps
	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor="+env.LogPath,
		"--",
		"sh", "-c", "cat "+testFile+" && sleep 2")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	require.NoError(t, cmd.Start())

	// Give it time to read the file (but not enough to finish sleeping)
	time.Sleep(500 * time.Millisecond)

	// The READ entry should be visible before the command exits
	assertLogLineContainsAll(t, env.LogPath, "READ", testFile)

	_ = cmd.Wait()
}

// TestE2E_MonitoringAccess_MonitorWithoutNetRules tests that when monitoring is enabled
// without net rules, the proxy-tunnel starts with deny-all and network access attempts
// by proxy-aware programs are logged.
func TestE2E_MonitoringAccess_MonitorWithoutNetRules(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)
	failIfNoStrace(t)

	host, port := testHTTPServer(t, "should not see this")

	tmpDir := testTempDir(t)
	logPath := filepath.Join(tmpDir, "access.log")

	// No net rules
	configPath := writeConfig(t, systemPaths())

	_ = runExecave(t, "", "--config", configPath,
		"--monitor="+logPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	// Denied network request logged
	assertLogLineContainsAll(t, logPath, "HTTP", host+":"+port, "DENY", "no-matching-rule")
}

// TestE2E_MonitoringAccess_AccessLogAfterSIGINT tests that the access log contains entries
// for operations that occurred before the child process is terminated by SIGINT.
func TestE2E_MonitoringAccess_AccessLogAfterSIGINT(t *testing.T) {
	env := newMonitorTest(t)

	result := env.runMonitoredWithInterrupt(t, systemPaths(), "sleep", "60")

	// Exit code 130 = 128 + SIGINT(2)
	assertExitCode(t, result, 130)

	assertLogExists(t, env.LogPath)
	logContent := env.readLog(t)
	assert.NotEmpty(t, logContent)
}

// TestE2E_MonitoringAccess_LogDeduplication tests that each unique (operation, target) pair
// appears in the log at most once, even when the resource is accessed multiple times.
func TestE2E_MonitoringAccess_LogDeduplication(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "file.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Read the same file three times
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Deduplicated to exactly one READ entry
	lines := 0
	for line := range strings.SplitSeq(logContent, "\n") {
		if strings.Contains(line, "READ") && strings.Contains(line, testFile) {
			lines++
		}
	}
	assert.Equal(t, 1, lines)
}

// TestE2E_MonitoringAccess_SymlinkResolutionHopsLogged tests that when a file is accessed
// through a symlink, each resolution hop is logged separately.
func TestE2E_MonitoringAccess_SymlinkResolutionHopsLogged(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	targetPath := filepath.Join(mountDir, "real.txt")

	createFile(t, targetPath, "target content")
	createSymlink(t, targetPath, linkPath)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 0)

	// Both the symlink hop and the resolved target are logged
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", targetPath, "OK", "fs:ro:"+mountDir)
}
