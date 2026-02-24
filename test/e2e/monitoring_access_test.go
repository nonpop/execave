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

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	dataFileRel, err := filepath.Rel(homeDir, dataFile)
	require.NoError(t, err)

	// Stderr contains the monitor URL
	assert.Contains(t, result.Stderr, "monitor running at http://127.0.0.1:")

	// Web UI displays entry with all four columns
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+dataFileRel, "OK", "fs:ro:"+dataDir)
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
		"--monitor",
		"--no-open",
		"--",
		"sh", "-c", "cat "+testFile+" && sleep 10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

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
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	testFileRel, err := filepath.Rel(homeDir, testFile)
	require.NoError(t, err)
	assert.Contains(t, webUI, "~/"+testFileRel)

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_MonitoringAccess_WebUISurvivesSandboxExit tests that the web UI remains
// accessible after the sandboxed command exits.
func TestE2E_MonitoringAccess_WebUISurvivesSandboxExit(t *testing.T) {
	env := newMonitorTest(t)

	dataFile := filepath.Join(env.TmpDir, "file.txt")
	createFile(t, dataFile, "test data")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"cat", dataFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdout strings.Builder
	cmd.Stdout = &stdout

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())

	// Read stderr, extract monitor URL, signal readiness when URL appears
	var monitorURL string
	var stderrOnce sync.Once
	stderrReady := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			if after, ok := strings.CutPrefix(scanner.Text(), "execave: monitor running at "); ok {
				monitorURL = after
				stderrOnce.Do(func() { close(stderrReady) })
			}
		}
		stderrOnce.Do(func() { close(stderrReady) })
	}()

	<-stderrReady
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Wait for the sandbox command to finish
	time.Sleep(500 * time.Millisecond)

	// Web UI is still accessible after sandbox exit
	webUI := fetchWebUI(t, monitorURL)
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	dataFileRel, err := filepath.Rel(homeDir, dataFile)
	require.NoError(t, err)
	assertWebUIHasEntry(t, webUI, "READ", "~/"+dataFileRel)

	// Clean up: send SIGINT to stop the server
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
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
	resp, err := client.Get(result.MonitorURL)
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
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	dataFileRel, err := filepath.Rel(homeDir, dataFile)
	require.NoError(t, err)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+dataFileRel, "OK")
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
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	testFileRel, err := filepath.Rel(homeDir, testFile)
	require.NoError(t, err)
	targetCell := `<td class="target">` + "~/" + testFileRel + `</td>`
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
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	linkPathRel, err := filepath.Rel(homeDir, linkPath)
	require.NoError(t, err)
	targetPathRel, err := filepath.Rel(homeDir, targetPath)
	require.NoError(t, err)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+linkPathRel, "OK", "fs:ro:"+mountDir)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+targetPathRel, "OK", "fs:ro:"+mountDir)
}

// TestE2E_MonitoringAccess_VerifyFilesystemEnforcementDecisionsAreAccuratelyLogged tests that
// sandbox enforcement and monitor logging work correctly together. This is
// the core integration test: when both --monitor and sandbox are active,
// enforcement decisions must be accurately logged.
func TestE2E_MonitoringAccess_VerifyFilesystemEnforcementDecisionsAreAccuratelyLogged(t *testing.T) {
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
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	allowedFileRel, err := filepath.Rel(homeDir, allowedFile)
	require.NoError(t, err)
	deniedFileRel, err := filepath.Rel(homeDir, deniedFile)
	require.NoError(t, err)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+allowedFileRel, "OK", "fs:ro:"+allowedFile)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+deniedFileRel, "DENY", "fs:none:"+deniedFile)
}

// TestE2E_MonitoringAccess_VerifyNetworkEnforcementDecisionsAreAccuratelyLogged tests that
// network enforcement and monitor logging work correctly together: allowed
// endpoints show OK with the matching rule and denied endpoints show DENY with
// the explicit deny rule.
func TestE2E_MonitoringAccess_VerifyNetworkEnforcementDecisionsAreAccuratelyLogged(t *testing.T) {
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

// TestE2E_MonitoringAccess_MonitorReflectsFilesystemRulePrecedenceCorrectly tests that most-specific rule
// precedence is correctly enforced and logged. This ensures both rule
// resolution systems (sandbox and monitor) agree on which rule applies.
func TestE2E_MonitoringAccess_MonitorReflectsFilesystemRulePrecedenceCorrectly(t *testing.T) {
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
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	projectFileRel, err := filepath.Rel(homeDir, projectFile)
	require.NoError(t, err)
	gitFileRel, err := filepath.Rel(homeDir, gitFile)
	require.NoError(t, err)
	assertWebUIHasEntry(t, result.WebUI, "WRITE", "~/"+projectFileRel, "OK", "fs:rw:"+projectDir)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+gitFileRel, "OK", "fs:ro:"+gitDir)
	assertWebUIHasEntry(t, result.WebUI, "WRITE", "~/"+gitFileRel, "DENY", "fs:ro:"+gitDir)
}

// TestE2E_MonitoringAccess_MonitorReflectsNetworkRulePrecedenceCorrectly tests that
// network rule specificity is correctly enforced and logged. A longer CIDR prefix
// deny rule must override a shorter CIDR prefix allow rule, and the monitor must
// show the more-specific rule — not the broad one.
func TestE2E_MonitoringAccess_MonitorReflectsNetworkRulePrecedenceCorrectly(t *testing.T) {
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

// TestE2E_MonitoringAccess_BarePathRelativeAccessesResolvedInAccessLog tests that bare-path
// syscalls (e.g., access()) with relative paths are resolved to absolute paths
// using tracked per-pid cwd, producing proper rule matching instead of UNKNOWN.
func TestE2E_MonitoringAccess_BarePathRelativeAccessesResolvedInAccessLog(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoGcc(t)

	// Create project dir with .git/config (target of the bare-path access call)
	projectDir := filepath.Join(env.TmpDir, "project")
	createFile(t, filepath.Join(projectDir, ".git", "config"), "[core]")

	// Compile a C program that calls access(".git/config", R_OK).
	// On Linux/glibc/x86_64, access() maps to the access syscall directly
	// (not faccessat), producing a bare-path line in strace output.
	cSource := filepath.Join(env.TmpDir, "access_test.c")
	cBinary := filepath.Join(env.TmpDir, "access_test")
	createFile(t, cSource, "#include <unistd.h>\nint main(void) { access(\".git/config\", R_OK); return 0; }\n")

	//nolint:gosec // G204: test code with controlled args
	cmd := exec.CommandContext(context.Background(), "gcc", "-o", cBinary, cSource)
	require.NoError(t, cmd.Run())

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Run the C program with cwd set to projectDir.
	// sh inherits cwd from bwrap, then cd changes it. The C program inherits
	// sh's cwd. The dynamic linker emits AT_FDCWD-annotated openat calls,
	// establishing the cwd for the pid. Then access(".git/config") resolves
	// against the tracked cwd.
	result := env.runMonitored(t, rules,
		"sh", "-c", "cd "+projectDir+" && "+cBinary)
	assertExitCode(t, result.execaveResult, 0)

	// The bare-path access should be resolved to absolute path with rule matching
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	gitConfigRel, err := filepath.Rel(homeDir, filepath.Join(projectDir, ".git", "config"))
	require.NoError(t, err)
	assertWebUIHasEntry(t, result.WebUI, "READ",
		"~/"+gitConfigRel, "OK", "fs:ro:"+env.TmpDir)
}

// TestE2E_MonitoringAccess_UnresolvedRelativePathWhenNoCwdTracked tests that bare-path
// syscalls from a pid with no tracked cwd produce UNKNOWN entries.
// This uses a minimal binary compiled with -nostdlib -static to avoid any
// AT_FDCWD-annotated calls (no dynamic linker, no runtime initialization).
func TestE2E_MonitoringAccess_UnresolvedRelativePathWhenNoCwdTracked(t *testing.T) {
	env := newMonitorTest(t)
	failIfNoGcc(t)

	// Build a minimal static binary that calls the access syscall with a relative
	// path and then exits. No libc/runtime means no AT_FDCWD-annotated calls,
	// so the monitor has no tracked cwd for this pid.
	cSource := filepath.Join(env.TmpDir, "bare_access.c")
	cBinary := filepath.Join(env.TmpDir, "bare_access")
	createFile(t, cSource, `
long sys_access(const char *path, int mode) {
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "0"(21), "D"(path), "S"(mode) : "rcx", "r11", "memory");
	return ret;
}
void sys_exit(int code) {
	__asm__ volatile("syscall" :: "a"(231), "D"(code));
	__builtin_unreachable();
}
void _start(void) {
	sys_access("untracked-relative/file.txt", 0);
	sys_exit(0);
}
`)
	//nolint:gosec // G204: test code with controlled args
	cmd := exec.CommandContext(context.Background(), "gcc", "-nostdlib", "-static", "-o", cBinary, cSource)
	require.NoError(t, cmd.Run())

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	result := env.runMonitored(t, rules, cBinary)
	assertExitCode(t, result.execaveResult, 0)

	// The relative path should appear as UNKNOWN since no cwd was tracked
	assertWebUIHasEntry(t, result.WebUI, "READ",
		"untracked-relative/file.txt", "UNKNOWN", "unresolved-relative-path")
}

// TestE2E_MonitoringAccess_DeniedOnlyDefaultView tests that the web UI shows
// the "Denied only" checkbox as checked by default, and that OK and DENY entries
// carry the correct data-result attributes for client-side filtering.
func TestE2E_MonitoringAccess_DeniedOnlyDefaultView(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	createFile(t, filepath.Join(dataDir, "file.txt"), "test data")

	rules := append(systemPaths(), "fs:ro:"+dataDir)
	result := env.runMonitored(t, rules, "cat", filepath.Join(dataDir, "file.txt"))
	assertExitCode(t, result.execaveResult, 0)

	// Denied-only checkbox is present and checked by default
	assert.Contains(t, result.WebUI, `id="denied-only-checkbox" checked`)
	// Apply-nolog checkbox is also present and checked by default
	assert.Contains(t, result.WebUI, `id="apply-nolog-checkbox" checked`)
}

// TestE2E_MonitoringAccess_FsNologRuleSuppressesEntries tests that fs:nolog rules
// mark matching entries with data-nolog="true" in the web UI HTML, enabling
// client-side nolog filtering.
func TestE2E_MonitoringAccess_FsNologRuleSuppressesEntries(t *testing.T) {
	env := newMonitorTest(t)

	cacheDir := filepath.Join(env.TmpDir, "project", "cache")
	cacheFile := filepath.Join(cacheDir, "data.bin")
	createFile(t, cacheFile, "cache data")

	projectDir := filepath.Join(env.TmpDir, "project")

	rules := append(systemPaths(),
		"fs:ro:"+projectDir,
		"fs:nolog:"+cacheDir,
	)
	result := env.runMonitored(t, rules, "cat", cacheFile)
	assertExitCode(t, result.execaveResult, 0)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	cacheFileRel, err := filepath.Rel(homeDir, cacheFile)
	require.NoError(t, err)

	// Entry is present in HTML but with data-nolog="true"
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+cacheFileRel, "data-nolog=\"true\"")
}

// TestE2E_MonitoringAccess_FsLogOverridesNolog tests that a more specific fs:log
// rule overrides a broader fs:nolog rule, marking the entry with data-nolog="false".
func TestE2E_MonitoringAccess_FsLogOverridesNolog(t *testing.T) {
	env := newMonitorTest(t)

	projectDir := filepath.Join(env.TmpDir, "project")
	secretDir := filepath.Join(projectDir, "secret")
	secretFile := filepath.Join(secretDir, "key.pem")
	createFile(t, secretFile, "secret")

	rules := append(systemPaths(),
		"fs:ro:"+projectDir,
		"fs:nolog:"+projectDir,
		"fs:log:"+secretDir,
	)
	result := env.runMonitored(t, rules, "cat", secretFile)
	assertExitCode(t, result.execaveResult, 0)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	secretFileRel, err := filepath.Rel(homeDir, secretFile)
	require.NoError(t, err)

	// Entry is present with data-nolog="false" because log rule overrides nolog
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+secretFileRel, "data-nolog=\"false\"")
}
