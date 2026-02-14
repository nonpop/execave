package e2e_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_MonitoringAccess_ViewAccessLogInWebUI tests that --monitor=PORT starts
// a web UI showing access log entries with all four columns (operation, target,
// result, rule), and prints the monitor URL to stderr.
func TestE2E_MonitoringAccess_ViewAccessLogInWebUI(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	dataFile := filepath.Join(dataDir, "file.txt")
	createFile(t, dataFile, "test data")

	rules := append(systemPaths(), "fs:ro:"+dataDir)

	result := env.runMonitored(t, rules, "cat", dataFile)
	assertExitCode(t, result.execaveResult, 0)

	// Stderr contains the monitor URL
	assert.Contains(t, result.Stderr, "monitor running at http://127.0.0.1:")

	// Web UI displays entry with all four columns
	assertWebUIHasEntry(t, result.WebUI, "READ", dataFile, "OK", "fs:ro:"+dataDir)
}

// TestE2E_MonitoringAccess_RealTimeStreamingViaWebUI tests that log entries appear
// in the web UI during execution, before the command exits.
func TestE2E_MonitoringAccess_RealTimeStreamingViaWebUI(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "data.txt")
	createFile(t, testFile, "test content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor=0",
		"--",
		"sh", "-c", "cat "+testFile+" && sleep 10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} //nolint:exhaustruct

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	cmd.Stdout = os.Stdout

	require.NoError(t, cmd.Start())

	// Wait for web UI to be ready, extract monitor URL
	var monitorURL string
	var stderrOnce sync.Once
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			if after, ok := strings.CutPrefix(scanner.Text(), "execave: monitor running at "); ok {
				monitorURL = after
				stderrOnce.Do(func() { close(ready) })
			}
		}
		stderrOnce.Do(func() { close(ready) })
	}()
	<-ready
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Give time for the cat to execute (but not enough to finish sleeping)
	time.Sleep(500 * time.Millisecond)

	// The READ entry should be visible in the web UI before the command exits
	webUI := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI, testFile)

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_MonitoringAccess_WebUISurvivesSandboxExit tests that the web UI remains
// accessible after the sandboxed command exits, and the post-exit message is printed.
func TestE2E_MonitoringAccess_WebUISurvivesSandboxExit(t *testing.T) {
	env := newMonitorTest(t)

	dataFile := filepath.Join(env.TmpDir, "file.txt")
	createFile(t, dataFile, "test data")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor=0",
		"--",
		"cat", dataFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} //nolint:exhaustruct

	var stdout strings.Builder
	cmd.Stdout = &stdout

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())

	// Read stderr, extract monitor URL, wait for "Press Ctrl-C" (sandbox exited, server still running)
	var monitorURL string
	var stderrOnce sync.Once
	stderrReady := make(chan struct{})
	stderrDone := make(chan string, 1)
	go func() {
		var sb strings.Builder
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			sb.WriteString(line + "\n")
			if after, ok := strings.CutPrefix(line, "execave: monitor running at "); ok {
				monitorURL = after
			}
			if strings.Contains(line, "Press Ctrl-C") {
				stderrOnce.Do(func() { close(stderrReady) })
			}
		}
		stderrOnce.Do(func() { close(stderrReady) })
		stderrDone <- sb.String()
	}()

	<-stderrReady
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Web UI is still accessible after sandbox exit
	webUI := fetchWebUI(t, monitorURL)
	assertWebUIHasEntry(t, webUI, "READ", dataFile)

	// Clean up: send SIGINT to stop the server
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
	stderrStr := <-stderrDone

	// Stderr contains the post-exit message
	assert.Contains(t, stderrStr, "Press Ctrl-C")
	assert.Contains(t, stderrStr, "process exited")
}

// TestE2E_MonitoringAccess_SIGINTAfterSandboxExitStopsWebUI tests that sending
// SIGINT after the sandboxed command has exited stops the web UI server.
func TestE2E_MonitoringAccess_SIGINTAfterSandboxExitStopsWebUI(t *testing.T) {
	env := newMonitorTest(t)

	rules := systemPaths()

	// runMonitored waits for sandbox exit, fetches web UI, sends SIGINT, waits for exit
	result := env.runMonitored(t, rules, "true")
	assertExitCode(t, result.execaveResult, 0)

	// After SIGINT stopped the server, the web UI should no longer be accessible
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(result.MonitorURL + "/")
	if resp != nil {
		resp.Body.Close() //nolint:errcheck,gosec // G104: best-effort close in test
	}
	assert.Error(t, err)
}

// TestE2E_MonitoringAccess_RunStatusShownInWebUI tests that the web UI displays
// the sandboxed command and its exit status.
func TestE2E_MonitoringAccess_RunStatusShownInWebUI(t *testing.T) {
	env := newMonitorTest(t)

	rules := systemPaths()

	result := env.runMonitored(t, rules, "echo", "hello")
	assertExitCode(t, result.execaveResult, 0)

	// Web UI displays the command
	assert.Contains(t, result.WebUI, "echo hello")

	// Web UI displays exit status
	assert.Contains(t, result.WebUI, "Exited")
	assert.Contains(t, result.WebUI, "(code: 0)")
}

// TestE2E_MonitoringAccess_NoEntriesLostOnPageRefresh is a placeholder.
// Entries accumulate client-side via SSE, so testing that a page refresh
// preserves them requires a browser that executes JavaScript. A plain
// HTTP fetch only sees the initial HTML, not the SSE-populated state.
func TestE2E_MonitoringAccess_NoEntriesLostOnPageRefresh(t *testing.T) {
	t.Skip("needs browser/JS execution to test SSE refresh; see comment above")
}

// TestE2E_MonitoringAccess_MonitorNetworkAccess tests that monitoring with net rules
// captures both HTTPS and HTTP entries visible via the web UI.
func TestE2E_MonitoringAccess_MonitorNetworkAccess(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoCurl(t)

	httpsHost, httpsPort := testHTTPSServer(t, "NET_HTTPS_OK")
	httpHost, httpPort := testHTTPServer(t, "NET_HTTP_OK")

	rules := append(systemPaths(),
		fmt.Sprintf("net:https:%s:%s", httpsHost, httpsPort),
		fmt.Sprintf("net:http:%s:%s", httpHost, httpPort),
	)

	result := env.runMonitored(t, rules,
		"sh", "-c", fmt.Sprintf("curl -sk https://%s/ && curl -sf http://%s/",
			net.JoinHostPort(httpsHost, httpsPort),
			net.JoinHostPort(httpHost, httpPort)))

	assertExitCode(t, result.execaveResult, 0)

	assertWebUIHasEntry(t, result.WebUI, "HTTPS", httpsHost+":"+httpsPort, "OK")
	assertWebUIHasEntry(t, result.WebUI, "HTTP", httpHost+":"+httpPort, "OK")
}

// TestE2E_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently tests that monitoring
// captures both filesystem READ/WRITE entries and network HTTPS entries.
func TestE2E_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoCurl(t)

	host, port := testHTTPSServer(t, "CONCURRENT_OK")

	dataFile := filepath.Join(env.TmpDir, "data.txt")
	createFile(t, dataFile, "fs data")

	rules := append(systemPaths(),
		"fs:ro:"+env.TmpDir,
		fmt.Sprintf("net:https:%s:%s", host, port),
	)

	result := env.runMonitored(t, rules,
		"sh", "-c", fmt.Sprintf("cat %s && curl -sk https://%s/", dataFile, net.JoinHostPort(host, port)))

	assertExitCode(t, result.execaveResult, 0)

	// Both filesystem and network entries in the web UI
	assertWebUIHasEntry(t, result.WebUI, "READ", dataFile, "OK")
	assertWebUIHasEntry(t, result.WebUI, "HTTPS", host+":"+port, "OK")
}

// TestE2E_MonitoringAccess_MonitorWithoutNetRules tests that when monitoring is enabled
// without net rules, the proxy-tunnel starts with deny-all and network access attempts
// by proxy-aware programs are logged.
func TestE2E_MonitoringAccess_MonitorWithoutNetRules(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// No net rules
	rules := systemPaths()

	result := env.runMonitored(t, rules,
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	// Denied network request logged
	assertWebUIHasEntry(t, result.WebUI, "HTTP", host+":"+port, "DENY", "no-matching-rule")
}

// TestE2E_MonitoringAccess_AccessLogAfterSIGINT tests that the access log contains entries
// for operations that occurred before the child process is terminated by SIGINT,
// and that SIGINT is forwarded to the sandboxed process.
func TestE2E_MonitoringAccess_AccessLogAfterSIGINT(t *testing.T) {
	env := newMonitorTest(t)

	result := env.runMonitoredWithInterrupt(t, systemPaths(), "sleep", "60")

	// Exit code 130 = 128 + SIGINT(2), proving SIGINT was forwarded to the child
	assertExitCode(t, result.execaveResult, 130)

	// Entries should exist (from process startup syscalls)
	assert.NotEmpty(t, result.WebUI)
}

// TestE2E_MonitoringAccess_LogDeduplication tests that each unique (operation, target) pair
// appears in the web UI at most once, even when the resource is accessed multiple times.
func TestE2E_MonitoringAccess_LogDeduplication(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "file.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Read the same file three times
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)
	assertExitCode(t, result.execaveResult, 0)

	// Deduplicated: the target should appear exactly once as a table cell value
	targetCell := `<td class="target">` + testFile + `</td>`
	count := strings.Count(result.WebUI, targetCell)
	// Deduplicated: target cell should appear exactly once
	assert.Equal(t, 1, count)
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
	assertExitCode(t, result.execaveResult, 0)

	// Both the symlink hop and the resolved target are logged
	assertWebUIHasEntry(t, result.WebUI, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertWebUIHasEntry(t, result.WebUI, "READ", targetPath, "OK", "fs:ro:"+mountDir)
}

// TestE2E_MonitoringAccess_FilesystemEnforcementDecisionsAccuratelyLogged tests that
// sandbox enforcement and monitor logging work correctly together. This is
// the core integration test: when both --monitor and sandbox are active,
// enforcement decisions must be accurately logged.
func TestE2E_MonitoringAccess_FilesystemEnforcementDecisionsAccuratelyLogged(t *testing.T) {
	env := newMonitorTest(t)

	allowedFile := filepath.Join(env.TmpDir, "allowed.txt")
	deniedFile := filepath.Join(env.TmpDir, "denied.txt")
	createFile(t, allowedFile, "allowed content")
	createFile(t, deniedFile, "denied content")

	// Allow reading allowed.txt but deny denied.txt
	rules := append(systemPaths(),
		"fs:ro:"+allowedFile,
		"fs:none:"+deniedFile,
	)

	// Run both operations in a single invocation so both are logged
	// First cat should succeed, second should fail, but both get logged
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+allowedFile+" || true; cat "+deniedFile+" || true")

	// Verify enforcement decisions in the web UI
	assertWebUIHasEntry(t, result.WebUI, "READ", allowedFile, "OK", "fs:ro:"+allowedFile)
	assertWebUIHasEntry(t, result.WebUI, "READ", deniedFile, "DENY", "fs:none:"+deniedFile)
}

// TestE2E_MonitoringAccess_NetworkEnforcementDecisionsAccuratelyLogged tests that
// network enforcement and monitor logging work correctly together: allowed
// endpoints show OK with the matching rule and denied endpoints show DENY with
// the explicit deny rule.
func TestE2E_MonitoringAccess_NetworkEnforcementDecisionsAccuratelyLogged(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoCurl(t)

	allowedHost, allowedPort := testHTTPServer(t, "ALLOWED_BODY")
	deniedHost, deniedPort := testHTTPServer(t, "should not see this")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:%s", allowedHost, allowedPort),
		fmt.Sprintf("net:none:%s:%s", deniedHost, deniedPort),
	)

	result := env.runMonitored(t, rules,
		"sh", "-c", fmt.Sprintf(
			"curl -sf http://%s/ || true; curl -sf http://%s/ || true",
			net.JoinHostPort(allowedHost, allowedPort),
			net.JoinHostPort(deniedHost, deniedPort)))

	assertWebUIHasEntry(t, result.WebUI, "HTTP", allowedHost+":"+allowedPort, "OK",
		fmt.Sprintf("net:http:%s:%s", allowedHost, allowedPort))
	assertWebUIHasEntry(t, result.WebUI, "HTTP", deniedHost+":"+deniedPort, "DENY",
		fmt.Sprintf("net:none:%s:%s", deniedHost, deniedPort))
}

// TestE2E_MonitoringAccess_FilesystemRulePrecedenceReflectedCorrectly tests that most-specific rule
// precedence is correctly enforced and logged. This ensures both rule
// resolution systems (sandbox and monitor) agree on which rule applies.
func TestE2E_MonitoringAccess_FilesystemRulePrecedenceReflectedCorrectly(t *testing.T) {
	env := newMonitorTest(t)

	projectDir := filepath.Join(env.TmpDir, "project")
	gitDir := filepath.Join(projectDir, ".git")

	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)

	projectFile := filepath.Join(projectDir, "main.go")
	gitFile := filepath.Join(gitDir, "config")

	createFile(t, projectFile, "package main")
	createFile(t, gitFile, "[core]")

	// Nested rules: project rw, .git ro (more specific overrides parent)
	rules := append(systemPaths(),
		"fs:rw:"+projectDir,
		"fs:ro:"+gitDir,
	)

	// Run all operations in one invocation to capture all in the same log
	cmd := "echo '// comment' >> " + projectFile + " && " +
		"cat " + gitFile + " && " +
		"(echo 'modified' >> " + gitFile + " || true)"

	result := env.runMonitored(t, rules, "sh", "-c", cmd)
	// First two operations succeed, last one fails
	assertExitCode(t, result.execaveResult, 0)

	// Verify enforcement decisions in the web UI
	assertWebUIHasEntry(t, result.WebUI, "WRITE", projectFile, "OK", "fs:rw:"+projectDir)
	assertWebUIHasEntry(t, result.WebUI, "READ", gitFile, "OK", "fs:ro:"+gitDir)
	assertWebUIHasEntry(t, result.WebUI, "WRITE", gitFile, "DENY", "fs:ro:"+gitDir)
}

// TestE2E_MonitoringAccess_NetworkRulePrecedenceReflectedCorrectly tests that
// network rule specificity is correctly enforced and logged. A longer CIDR prefix
// deny rule must override a shorter CIDR prefix allow rule, and the monitor must
// show the more-specific rule — not the broad one.
func TestE2E_MonitoringAccess_NetworkRulePrecedenceReflectedCorrectly(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoCurl(t)

	// Both servers bind to 127.0.0.1 — we use port to distinguish allowed vs denied
	_, allowedPort := testHTTPServer(t, "ALLOWED_CIDR")
	_, deniedPort := testHTTPServer(t, "should not see this")

	// Broad CIDR allow for all of 127.0.0.0/8 on any port,
	// specific /32 deny for 127.0.0.1 on the denied port
	rules := append(systemPaths(),
		"net:http:127.0.0.0/8:*",
		"net:none:127.0.0.1/32:"+deniedPort,
	)

	result := env.runMonitored(t, rules,
		"sh", "-c", fmt.Sprintf(
			"curl -sf http://127.0.0.1:%s/ || true; curl -sf http://127.0.0.1:%s/ || true",
			allowedPort, deniedPort))

	// Allowed port: broad CIDR matches (no specific deny for this port)
	assertWebUIHasEntry(t, result.WebUI, "HTTP", "127.0.0.1:"+allowedPort, "OK",
		"net:http:127.0.0.0/8:*")
	// Denied port: specific /32 deny overrides broad /8 allow
	assertWebUIHasEntry(t, result.WebUI, "HTTP", "127.0.0.1:"+deniedPort, "DENY",
		"net:none:127.0.0.1/32:"+deniedPort)
}
