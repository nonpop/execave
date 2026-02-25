package e2e_test

import (
	"bufio"
	"context"
	"fmt"
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
	s := newScenario(t)
	data := s.givenDir("data")
	dataFile := data.file("file.txt", "test data")

	s.givenRules("fs:ro:" + data.String())

	s.whenRunMonitored("cat", dataFile)

	s.thenExitCode(0)
	s.thenStderrContains("monitor running at http://127.0.0.1:")
	s.thenWebUIHasEntry("READ", data.rel("file.txt"), "OK", "fs:ro:"+data.String())
}

// TestE2E_MonitoringAccess_RealTimeStreamingViaWebUI tests that log entries appear
// in the web UI during execution, before the command exits.
func TestE2E_MonitoringAccess_RealTimeStreamingViaWebUI(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.file("data.txt", "test content")

	rules := append(systemPaths(), "fs:ro:"+data.String())
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
	require.NotEmpty(t, monitorURL)

	time.Sleep(500 * time.Millisecond)

	webUI := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI, data.rel("data.txt"))

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_MonitoringAccess_WebUISurvivesSandboxExit tests that the web UI remains
// accessible after the sandboxed command exits.
func TestE2E_MonitoringAccess_WebUISurvivesSandboxExit(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	dataFile := data.file("file.txt", "test data")

	rules := append(systemPaths(), "fs:ro:"+data.String())
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
	require.NotEmpty(t, monitorURL)

	time.Sleep(500 * time.Millisecond)

	webUI := fetchWebUI(t, monitorURL)
	assertWebUIHasEntry(t, webUI, "READ", data.rel("file.txt"))

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_MonitoringAccess_SIGINTAfterSandboxExitStopsWebUI tests that sending
// SIGINT after the sandboxed command has exited stops the web UI server.
func TestE2E_MonitoringAccess_SIGINTAfterSandboxExitStopsWebUI(t *testing.T) {
	s := newScenario(t)

	s.givenRules()

	s.whenRunMonitored("true")

	s.thenExitCode(0)
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(s.monitorURL)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck,gosec // G104: best-effort close in test
	}
	assert.Error(t, err)
}

// TestE2E_MonitoringAccess_RunStatusShownInWebUI tests that the web UI displays
// the sandboxed command and its exit status.
func TestE2E_MonitoringAccess_RunStatusShownInWebUI(t *testing.T) {
	s := newScenario(t)

	s.givenRules()

	s.whenRunMonitored("echo", "hello")

	s.thenExitCode(0)
	s.thenWebUIContains("echo hello")
	s.thenWebUIContains("Exited")
	s.thenWebUIContains("(code: 0)")
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
	s := newScenario(t)
	s.givenCurl()

	https := s.givenHTTPSServer("NET_HTTPS_OK")
	httpSrv := s.givenHTTPServer("NET_HTTP_OK")

	s.givenRules(
		"net:http:"+https.addr(),
		"net:http:"+httpSrv.addr(),
	)

	s.whenRunMonitored("sh", "-c", fmt.Sprintf("curl -sk https://%s/ && curl -sf http://%s/",
		https.hostPort(), httpSrv.hostPort()))

	s.thenExitCode(0)
	s.thenWebUIHasEntry("HTTP", https.addr(), "OK")
	s.thenWebUIHasEntry("HTTP", httpSrv.addr(), "OK")
}

// TestE2E_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently tests that monitoring
// captures both filesystem READ/WRITE entries and network HTTPS entries.
func TestE2E_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPSServer("CONCURRENT_OK")
	data := s.givenDir("data")
	dataFile := data.file("data.txt", "fs data")

	s.givenRules(
		"fs:ro:"+data.String(),
		"net:http:"+srv.addr(),
	)

	s.whenRunMonitored("sh", "-c", fmt.Sprintf("cat %s && curl -sk https://%s/", dataFile, srv.hostPort()))

	s.thenExitCode(0)
	// Both filesystem and network entries in the web UI
	s.thenWebUIHasEntry("READ", data.rel("data.txt"), "OK")
	s.thenWebUIHasEntry("HTTP", srv.addr(), "OK")
}

// TestE2E_MonitoringAccess_MonitorWithoutNetRules tests that when monitoring is enabled
// without net rules, the proxy-tunnel starts with deny-all and network access attempts
// by proxy-aware programs are logged.
func TestE2E_MonitoringAccess_MonitorWithoutNetRules(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPServer("should not see this")

	s.givenRules() // no net rules

	s.whenRunMonitored("curl", "-sf", "--max-time", "5",
		fmt.Sprintf("http://%s/", srv.hostPort()))

	// Denied network request logged
	s.thenWebUIHasEntry("HTTP", srv.addr(), "DENY", "no-matching-rule")
}

// TestE2E_MonitoringAccess_AccessLogAfterSIGINT tests that the access log contains entries
// for operations that occurred before the child process is terminated by SIGINT,
// and that SIGINT is forwarded to the sandboxed process.
func TestE2E_MonitoringAccess_AccessLogAfterSIGINT(t *testing.T) {
	s := newScenario(t)

	s.givenRules()

	s.whenRunMonitoredWithInterrupt("sleep", "60")

	s.thenExitCode(130) // 128 + SIGINT(2), proving SIGINT was forwarded to the child
	// Entries should exist (from process startup syscalls)
	require.NotEmpty(t, s.lastWebUI)
}

// TestE2E_MonitoringAccess_LogDeduplication tests that each unique (operation, target) pair
// appears in the web UI at most once, even when the resource is accessed multiple times.
func TestE2E_MonitoringAccess_LogDeduplication(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.file("file.txt", "content")

	s.givenRules("fs:ro:" + data.String())

	// Read the same file three times
	s.whenRunMonitored("sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)

	// Deduplicated: target cell should appear exactly once
	s.thenExitCode(0)
	targetCell := `<td class="target">` + data.rel("file.txt") + `</td>`
	assert.Equal(t, 1, s.thenWebUICountOf(targetCell))
}

// TestE2E_MonitoringAccess_SymlinkResolutionHopsLogged tests that when a file is accessed
// through a symlink, each resolution hop is logged separately.
func TestE2E_MonitoringAccess_SymlinkResolutionHopsLogged(t *testing.T) {
	s := newScenario(t)
	mount := s.givenDir("mount")
	targetPath := mount.file("real.txt", "target content")
	linkPath := mount.join("link.txt")
	s.givenSymlink(targetPath, linkPath)

	s.givenRules("fs:ro:" + mount.String())

	s.whenRunMonitored("cat", linkPath)

	// Both the symlink hop and the resolved target are logged
	s.thenExitCode(0)
	s.thenWebUIHasEntry("READ", mount.rel("link.txt"), "OK", "fs:ro:"+mount.String())
	s.thenWebUIHasEntry("READ", mount.rel("real.txt"), "OK", "fs:ro:"+mount.String())
}

// TestE2E_MonitoringAccess_VerifyFilesystemEnforcementDecisionsAreAccuratelyLogged tests that
// sandbox enforcement and monitor logging work correctly together.
func TestE2E_MonitoringAccess_VerifyFilesystemEnforcementDecisionsAreAccuratelyLogged(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	allowedFile := data.file("allowed.txt", "allowed content")
	deniedFile := data.file("denied.txt", "denied content")

	s.givenRules("fs:ro:"+allowedFile, "fs:none:"+deniedFile)

	// Run both operations in a single invocation so both are logged
	s.whenRunMonitored("sh", "-c", "cat "+allowedFile+" || true; cat "+deniedFile+" || true")

	// Verify enforcement decisions in the web UI
	s.thenWebUIHasEntry("READ", data.rel("allowed.txt"), "OK", "fs:ro:"+allowedFile)
	s.thenWebUIHasEntry("READ", data.rel("denied.txt"), "DENY", "fs:none:"+deniedFile)
}

// TestE2E_MonitoringAccess_VerifyNetworkEnforcementDecisionsAreAccuratelyLogged tests that
// network enforcement and monitor logging work correctly together.
func TestE2E_MonitoringAccess_VerifyNetworkEnforcementDecisionsAreAccuratelyLogged(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	allowed := s.givenHTTPServer("ALLOWED_BODY")
	denied := s.givenHTTPServer("should not see this")

	s.givenRules(
		"net:http:"+allowed.addr(),
		"net:none:"+denied.addr(),
	)

	s.whenRunMonitored("sh", "-c", fmt.Sprintf(
		"curl -sf http://%s/ || true; curl -sf http://%s/ || true",
		allowed.hostPort(), denied.hostPort()))

	s.thenWebUIHasEntry("HTTP", allowed.addr(), "OK",
		"net:http:"+allowed.addr())
	s.thenWebUIHasEntry("HTTP", denied.addr(), "DENY",
		"net:none:"+denied.addr())
}

// TestE2E_MonitoringAccess_MonitorReflectsFilesystemRulePrecedenceCorrectly tests that most-specific rule
// precedence is correctly enforced and logged.
func TestE2E_MonitoringAccess_MonitorReflectsFilesystemRulePrecedenceCorrectly(t *testing.T) {
	s := newScenario(t)
	project := s.givenDir("project")
	gitDir := project.join(".git")
	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)

	projectFile := project.file("main.go", "package main")
	gitFile := project.file(".git/config", "[core]")

	s.givenRules("fs:rw:"+project.String(), "fs:ro:"+gitDir)

	// Run all operations in one invocation to capture all in the same log
	cmd := "echo '// comment' >> " + projectFile + " && " +
		"cat " + gitFile + " && " +
		"(echo 'modified' >> " + gitFile + " || true)"
	s.whenRunMonitored("sh", "-c", cmd)

	// First two operations succeed, last one fails
	s.thenExitCode(0)
	s.thenWebUIHasEntry("WRITE", project.rel("main.go"), "OK", "fs:rw:"+project.String())
	s.thenWebUIHasEntry("READ", project.rel(".git/config"), "OK", "fs:ro:"+gitDir)
	s.thenWebUIHasEntry("WRITE", project.rel(".git/config"), "DENY", "fs:ro:"+gitDir)
}

// TestE2E_MonitoringAccess_MonitorReflectsNetworkRulePrecedenceCorrectly tests that
// network rule specificity is correctly enforced and logged.
func TestE2E_MonitoringAccess_MonitorReflectsNetworkRulePrecedenceCorrectly(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	_, allowedPort := testHTTPServer(t, "ALLOWED_CIDR")
	_, deniedPort := testHTTPServer(t, "should not see this")

	s.givenRules(
		"net:http:127.0.0.0/8:*",
		"net:none:127.0.0.1/32:"+deniedPort,
	)

	s.whenRunMonitored("sh", "-c", fmt.Sprintf(
		"curl -sf http://127.0.0.1:%s/ || true; curl -sf http://127.0.0.1:%s/ || true",
		allowedPort, deniedPort))

	// Allowed port: broad CIDR matches (no specific deny for this port)
	s.thenWebUIHasEntry("HTTP", "127.0.0.1:"+allowedPort, "OK", "net:http:127.0.0.0/8:*")
	// Denied port: specific /32 deny overrides broad /8 allow
	s.thenWebUIHasEntry("HTTP", "127.0.0.1:"+deniedPort, "DENY", "net:none:127.0.0.1/32:"+deniedPort)
}

// TestE2E_MonitoringAccess_BarePathRelativeAccessesResolvedInAccessLog tests that bare-path
// syscalls (e.g., access()) with relative paths are resolved to absolute paths
// using tracked per-pid cwd, producing proper rule matching instead of UNKNOWN.
func TestE2E_MonitoringAccess_BarePathRelativeAccessesResolvedInAccessLog(t *testing.T) {
	s := newScenario(t)
	s.givenGcc()

	project := s.givenDir("project")
	project.file(".git/config", "[core]")

	cSource := filepath.Join(s.tmpDir, "access_test.c")
	cBinary := filepath.Join(s.tmpDir, "access_test")
	createFile(t, cSource, "#include <unistd.h>\nint main(void) { access(\".git/config\", R_OK); return 0; }\n")

	//nolint:gosec // G204: test code with controlled args
	cmd := exec.CommandContext(context.Background(), "gcc", "-o", cBinary, cSource)
	require.NoError(t, cmd.Run())

	s.givenRules("fs:ro:" + testDir(s.tmpDir).String())

	s.whenRunMonitored("sh", "-c", "cd "+project.String()+" && "+cBinary)

	// The bare-path access should be resolved to absolute path with rule matching
	s.thenExitCode(0)
	s.thenWebUIHasEntry("READ", project.rel(".git/config"), "OK",
		"fs:ro:"+testDir(s.tmpDir).String())
}

// TestE2E_MonitoringAccess_UnresolvedRelativePathWhenNoCwdTracked tests that bare-path
// syscalls from a pid with no tracked cwd produce UNKNOWN entries.
func TestE2E_MonitoringAccess_UnresolvedRelativePathWhenNoCwdTracked(t *testing.T) {
	s := newScenario(t)
	s.givenGcc()

	cSource := filepath.Join(s.tmpDir, "bare_access.c")
	cBinary := filepath.Join(s.tmpDir, "bare_access")
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

	s.givenRules("fs:ro:" + testDir(s.tmpDir).String())

	s.whenRunMonitored(cBinary)

	// The relative path should appear as UNKNOWN since no cwd was tracked
	s.thenExitCode(0)
	s.thenWebUIHasEntry("READ", "untracked-relative/file.txt", "UNKNOWN", "unresolved-relative-path")
}

// TestE2E_MonitoringAccess_DeniedOnlyDefaultView tests that the web UI shows
// the "Denied only" checkbox as checked by default.
func TestE2E_MonitoringAccess_DeniedOnlyDefaultView(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	data.file("file.txt", "test data")

	s.givenRules("fs:ro:" + data.String())

	s.whenRunMonitored("cat", data.join("file.txt"))

	// Denied-only checkbox is present and checked by default
	s.thenExitCode(0)
	s.thenWebUIContains(`id="denied-only-checkbox" checked`)
	// Apply-nolog checkbox is also present and checked by default
	s.thenWebUIContains(`id="apply-nolog-checkbox" checked`)
}

// TestE2E_MonitoringAccess_FsNologRuleSuppressesEntries tests that fs:nolog rules
// mark matching entries with data-nolog="true" in the web UI HTML.
func TestE2E_MonitoringAccess_FsNologRuleSuppressesEntries(t *testing.T) {
	s := newScenario(t)
	project := s.givenDir("project")
	cacheDir := project.join("cache")
	cacheFile := project.file("cache/data.bin", "cache data")

	s.givenRules("fs:ro:"+project.String(), "fs:nolog:"+cacheDir)

	s.whenRunMonitored("cat", cacheFile)

	// Entry is present in HTML but with data-nolog="true"
	s.thenExitCode(0)
	s.thenWebUIHasEntry("READ", project.rel("cache/data.bin"), "data-nolog=\"true\"")
}

// TestE2E_MonitoringAccess_FsLogOverridesNolog tests that a more specific fs:log
// rule overrides a broader fs:nolog rule.
func TestE2E_MonitoringAccess_FsLogOverridesNolog(t *testing.T) {
	s := newScenario(t)
	project := s.givenDir("project")
	secretDir := project.join("secret")
	secretFile := project.file("secret/key.pem", "secret")

	s.givenRules(
		"fs:ro:"+project.String(),
		"fs:nolog:"+project.String(),
		"fs:log:"+secretDir,
	)

	s.whenRunMonitored("cat", secretFile)

	// Entry is present with data-nolog="false" because log rule overrides nolog
	s.thenExitCode(0)
	s.thenWebUIHasEntry("READ", project.rel("secret/key.pem"), "data-nolog=\"false\"")
}
