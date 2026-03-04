package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_MonitoringAccess_ViewAccessLogInTextOutput tests that monitor --output=- writes
// access log entries with all four columns (operation, target, result, rule) to stderr.
func TestE2E_MonitoringAccess_ViewAccessLogInTextOutput(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	dataFile := data.file("file.txt", "test data")

	s.givenRules("fs:ro:" + data.String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", dataFile)

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK", "fs:ro:"+data.String())
}

// TestE2E_MonitoringAccess_MonitorNetworkAccess tests that monitoring with net rules
// captures both HTTPS and HTTP entries in the text log.
func TestE2E_MonitoringAccess_MonitorNetworkAccess(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	https := s.givenHTTPSServer("NET_HTTPS_OK")
	httpSrv := s.givenHTTPServer("NET_HTTP_OK")

	s.givenRules(
		"net:http:"+https.addr(),
		"net:http:"+httpSrv.addr(),
	)

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", fmt.Sprintf("curl -sk https://%s/ && curl -sf http://%s/",
			https.hostPort(), httpSrv.hostPort()))

	s.thenExitCode(0)
	s.thenStderrHasEntry("HTTP", https.addr(), "OK")
	s.thenStderrHasEntry("HTTP", httpSrv.addr(), "OK")
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

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", fmt.Sprintf("cat %s && curl -sk https://%s/", dataFile, srv.hostPort()))

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", data.rel("data.txt"), "OK")
	s.thenStderrHasEntry("HTTP", srv.addr(), "OK")
}

// TestE2E_MonitoringAccess_MonitorWithoutNetRules tests that when monitoring is enabled
// without net rules, the proxy-tunnel starts with deny-all and network access attempts
// by proxy-aware programs are logged.
func TestE2E_MonitoringAccess_MonitorWithoutNetRules(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPServer("should not see this")

	s.givenRules() // no net rules

	s.whenRunTextLog("-", "curl", "-sf", "--max-time", "5",
		fmt.Sprintf("http://%s/", srv.hostPort()))

	// Denied network request logged
	s.thenStderrHasEntry("HTTP", srv.addr(), "DENY", "no-matching-rule")
}

// TestE2E_MonitoringAccess_AccessLogAfterSIGINT tests that SIGINT is forwarded to the
// sandboxed process and the process exits with code 130 (128+SIGINT).
func TestE2E_MonitoringAccess_AccessLogAfterSIGINT(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	s.givenRules()

	logFile := filepath.Join(s.tmpDir, "access.log")
	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", s.configPath,
		"monitor", "--output="+logFile,
		"--",
		"sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	require.NoError(t, cmd.Start())

	// Wait for strace and the child process to start before sending SIGINT
	time.Sleep(500 * time.Millisecond)

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	waitErr := cmd.Wait()

	var exitCode int
	if waitErr != nil {
		exitErr := new(exec.ExitError)
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	assert.Equal(t, 130, exitCode) // 128 + SIGINT(2), proving SIGINT was forwarded to the child
}

// TestE2E_MonitoringAccess_LogDeduplication tests that each unique (operation, target) pair
// appears in the text log at most once, even when the resource is accessed multiple times.
func TestE2E_MonitoringAccess_LogDeduplication(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.file("file.txt", "content")

	s.givenRules("fs:ro:" + data.String())

	// Read the same file three times
	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)

	// Deduplicated: target should appear exactly once in stderr
	s.thenExitCode(0)
	assert.Equal(t, 1, strings.Count(s.lastResult.Stderr, data.rel("file.txt")))
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

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", linkPath)

	// Both the symlink hop and the resolved target are logged
	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", mount.rel("link.txt"), "OK", "fs:ro:"+mount.String())
	s.thenStderrHasEntry("READ", mount.rel("real.txt"), "OK", "fs:ro:"+mount.String())
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
	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", "cat "+allowedFile+" || true; cat "+deniedFile+" || true")

	// Verify enforcement decisions in the text log
	s.thenStderrHasEntry("READ", data.rel("allowed.txt"), "OK", "fs:ro:"+allowedFile)
	s.thenStderrHasEntry("READ", data.rel("denied.txt"), "DENY", "fs:none:"+deniedFile)
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

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", fmt.Sprintf(
			"curl -sf http://%s/ || true; curl -sf http://%s/ || true",
			allowed.hostPort(), denied.hostPort()))

	s.thenStderrHasEntry("HTTP", allowed.addr(), "OK", "net:http:"+allowed.addr())
	s.thenStderrHasEntry("HTTP", denied.addr(), "DENY", "net:none:"+denied.addr())
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
	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "sh", "-c", cmd)

	// First two operations succeed, last one fails
	s.thenExitCode(0)
	s.thenStderrHasEntry("WRITE", project.rel("main.go"), "OK", "fs:rw:"+project.String())
	s.thenStderrHasEntry("READ", project.rel(".git/config"), "OK", "fs:ro:"+gitDir)
	s.thenStderrHasEntry("WRITE", project.rel(".git/config"), "DENY", "fs:ro:"+gitDir)
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

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", fmt.Sprintf(
			"curl -sf http://127.0.0.1:%s/ || true; curl -sf http://127.0.0.1:%s/ || true",
			allowedPort, deniedPort))

	// Allowed port: broad CIDR matches (no specific deny for this port)
	s.thenStderrHasEntry("HTTP", "127.0.0.1:"+allowedPort, "OK", "net:http:127.0.0.0/8:*")
	// Denied port: specific /32 deny overrides broad /8 allow
	s.thenStderrHasEntry("HTTP", "127.0.0.1:"+deniedPort, "DENY", "net:none:127.0.0.1/32:"+deniedPort)
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

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", "cd "+project.String()+" && "+cBinary)

	// The bare-path access should be resolved to absolute path with rule matching
	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", project.rel(".git/config"), "OK",
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

	s.whenRunTextLog("-", cBinary)

	// The relative path should appear as UNKNOWN since no cwd was tracked
	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", "untracked-relative/file.txt", "UNKNOWN", "unresolved-relative-path")
}

// TestE2E_MonitoringAccess_DeniedOnlyDefaultView tests that by default the text log
// does not include OK entries.
func TestE2E_MonitoringAccess_DeniedOnlyDefaultView(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	data.file("file.txt", "test data")

	s.givenRules("fs:ro:" + data.String())

	s.whenRunTextLog("-", "cat", data.join("file.txt"))

	s.thenExitCode(0)
	// OK entries are absent from stderr by default
	s.thenStderrNotContains(data.rel("file.txt"))
}

// TestE2E_MonitoringAccess_FsNologRuleSuppressesEntries tests that fs:nolog rules
// suppress matching entries from the text log by default.
func TestE2E_MonitoringAccess_FsNologRuleSuppressesEntries(t *testing.T) {
	s := newScenario(t)
	project := s.givenDir("project")
	cacheDir := project.join("cache")
	cacheFile := project.file("cache/data.bin", "cache data")

	s.givenRules("fs:ro:"+project.String(), "fs:nolog:"+cacheDir)

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", cacheFile)

	// Entry is suppressed because of nolog rule
	s.thenExitCode(0)
	s.thenStderrNotContains(project.rel("cache/data.bin"))
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

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", secretFile)

	// Entry appears because log rule overrides nolog
	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", project.rel("secret/key.pem"), "OK")
}

// TestE2E_NoSandbox_UnenforcedEntriesAppearInLog verifies that --no-sandbox --monitor
// produces UNENFORCED entries (not DENY) for all accesses.
// TestE2E_MonitoringAccess_ObserveNativeNetworkAccessesWithoutIsolation verifies that in
// --no-sandbox --monitor mode, proxy-aware network requests are forwarded (not blocked)
// even when no net rule matches, and logged as UNENFORCED.
func TestE2E_MonitoringAccess_ObserveNativeNetworkAccessesWithoutIsolation(t *testing.T) {
	failIfNoStrace(t)
	s := newScenario(t)
	s.givenCurl()

	srv := s.givenHTTPServer("NATIVE_NET_OK")

	// No net rules — proxy starts with deny-all, but in no-sandbox mode it must not block.
	s.givenRules()

	s.whenRunNoSandboxMonitorFile("-",
		"curl", "-sf", fmt.Sprintf("http://%s/", srv.hostPort()))

	// Request must succeed (not blocked with 403).
	s.thenExitCode(0)
	s.thenStdoutContains("NATIVE_NET_OK")
	// Network access must be logged as UNENFORCED.
	s.thenStderrHasEntry("HTTP", srv.addr(), "UNENFORCED")
}

// TestE2E_NoSandbox_UnenforcedEntriesAppearInLog verifies that --no-sandbox --monitor
// produces UNENFORCED entries (not DENY) for all accesses.
func TestE2E_NoSandbox_UnenforcedEntriesAppearInLog(t *testing.T) {
	failIfNoStrace(t)
	s := newScenario(t)
	data := s.givenDir("data")
	data.file("allowed.txt", "allowed")
	blocked := s.givenDir("blocked")
	blocked.file("secret.txt", "secret")

	// Only allow the data directory; blocked directory has no rule.
	s.givenRules("fs:ro:" + data.String())

	s.whenRunNoSandboxMonitorFile("-", "cat", blocked.join("secret.txt"))

	// In no-sandbox mode the process is not blocked; cat still reads the file.
	s.thenExitCode(0)
	// Result must be UNENFORCED, not DENY — sandbox was not active.
	s.thenStderrHasEntry("READ", blocked.rel("secret.txt"), "UNENFORCED")
}

// TestE2E_NoSandbox_WithoutMonitorExitsError verifies that --no-sandbox on root
// exits with a non-zero code and does not execute the command.
func TestE2E_NoSandbox_WithoutMonitorExitsError(t *testing.T) {
	s := newScenario(t)
	s.givenRules()
	s.whenRunNoSandbox("true")
	s.thenExitCodeNonZero()
	s.thenStderrContains("unknown flag: --no-sandbox")
}

// TestE2E_NoSandbox_WritesLogToFile verifies that --no-sandbox --monitor=<file>
// writes the access log to the specified file.
func TestE2E_NoSandbox_WritesLogToFile(t *testing.T) {
	failIfNoStrace(t)
	s := newScenario(t)
	blocked := s.givenDir("blocked")
	blocked.file("secret.txt", "secret")
	s.givenRules()

	logFile := filepath.Join(t.TempDir(), "access.log")

	s.whenRunNoSandboxMonitorFile(logFile, "cat", blocked.join("secret.txt"))

	content, err := os.ReadFile(logFile) //nolint:gosec // test-controlled path
	require.NoError(t, err)
	assert.Contains(t, string(content), "UNENFORCED")
}

// bpfPythonCmd is the python3 one-liner that invokes the bpf syscall (nr 321 on x86_64).
const bpfPythonCmd = "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)"

// bpfRebootPythonCmd invokes bpf and reboot (nr 169) with invalid magic (safe: returns EINVAL).
const bpfRebootPythonCmd = "import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(169,0,0,0)"

// requireAMD64 skips the test on non-x86_64 architectures where syscall numbers are different.
func requireAMD64(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("test requires amd64 (got %s)", runtime.GOARCH)
	}
}

// TestE2E_MonitoringAccess_ViewSeccompDeniedSyscallAttemptsInAccessLog tests that when
// seccomp filtering is active, a blocked syscall attempt appears as a SYSCALL DENY entry.
func TestE2E_MonitoringAccess_ViewSeccompDeniedSyscallAttemptsInAccessLog(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules()

	s.whenRunTextLog("-", "python3", "-c", bpfPythonCmd)

	s.thenStderrHasEntry("SYSCALL", "bpf", "DENY", "seccomp")
}

// TestE2E_MonitoringAccess_VerifySeccompFilterIsActiveByPresenceOfSyscallEntries tests that
// SYSCALL entries appear when seccomp is active and disappear with --allow-all-syscalls.
func TestE2E_MonitoringAccess_VerifySeccompFilterIsActiveByPresenceOfSyscallEntries(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules()

	s.whenRunTextLog("-", "python3", "-c", bpfPythonCmd)
	s.thenStderrHasEntry("SYSCALL", "bpf", "DENY", "seccomp")

	s.whenRunTextLogWithFlags([]string{"--allow-all-syscalls"}, "python3", "-c", bpfPythonCmd)
	s.thenStderrNotContains("SYSCALL")
}

// TestE2E_MonitoringAccess_SeccompDeniedSyscallEntriesDeduplicated tests that repeated
// attempts of the same blocked syscall produce exactly one SYSCALL entry in the log.
func TestE2E_MonitoringAccess_SeccompDeniedSyscallEntriesDeduplicated(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules()

	s.whenRunTextLog("-", "python3", "-c",
		"import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(321,0,0,0)")

	s.thenStderrHasEntry("SYSCALL", "bpf", "DENY", "seccomp")
	var count int
	for line := range strings.SplitSeq(s.lastResult.Stderr, "\n") {
		if strings.Contains(line, "SYSCALL") && strings.Contains(line, "bpf") {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// TestE2E_MonitoringAccess_SuppressExpectedSyscallDenialsWithSyscallNolog tests that a
// syscall:nolog rule hides the DENY entry by default and reveals it with --show-nolog.
func TestE2E_MonitoringAccess_SuppressExpectedSyscallDenialsWithSyscallNolog(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules("syscall:nolog:bpf")

	s.whenRunTextLog("-", "python3", "-c", bpfPythonCmd)
	s.thenStderrNotContains("bpf")

	s.whenRunTextLogWithFlags([]string{"--show-nolog"}, "python3", "-c", bpfPythonCmd)
	s.thenStderrHasEntry("SYSCALL", "bpf", "DENY")
}

// TestE2E_MonitoringAccess_AllowedSyscallLoggedAsOk tests that a syscall:allow rule causes
// the syscall to appear as SYSCALL OK when --show-allowed is used.
func TestE2E_MonitoringAccess_AllowedSyscallLoggedAsOk(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules("syscall:allow:bpf")

	s.whenRunTextLog("-", "python3", "-c", bpfPythonCmd)
	s.thenStderrNotContains("bpf")

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "python3", "-c", bpfPythonCmd)
	s.thenStderrHasEntry("SYSCALL", "bpf", "OK", "syscall:allow:bpf")
}
