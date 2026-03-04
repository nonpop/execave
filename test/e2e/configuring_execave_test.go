package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_ConfiguringExecave_DefaultConfigLocation tests that execave reads ./execave.toml
// from the current working directory by default.
func TestE2E_ConfiguringExecave_DefaultConfigLocation(t *testing.T) {
	s := newScenario(t)
	workDir := s.givenDir("work")

	s.givenRulesInDir(workDir.String())

	s.whenRunWithDefaultConfig(workDir.String(), "echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

// TestE2E_ConfiguringExecave_CustomConfigPathViaConfig tests that --config overrides
// the default config location.
func TestE2E_ConfiguringExecave_CustomConfigPathViaConfig(t *testing.T) {
	s := newScenario(t)

	s.givenRules()

	s.whenRun("echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

// TestE2E_ConfiguringExecave_MissingConfigFileShowsError tests that a missing config file
// produces a clear error message.
func TestE2E_ConfiguringExecave_MissingConfigFileShowsError(t *testing.T) {
	result := runExecave(t, "", "--config", "/nonexistent/config.toml", "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "config file not found")
}

// TestE2E_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution tests that a malformed
// rule is rejected at config load time and the command never executes.
func TestE2E_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:readonly:/home/user")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("invalid permission type")
}

// TestE2E_ConfiguringExecave_InvalidNetActionRejected tests that rules with unrecognized
// net actions are rejected before command execution.
func TestE2E_ConfiguringExecave_InvalidNetActionRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("net:dns:example.com:53")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("invalid action")
}

// TestE2E_ConfiguringExecave_DuplicateFilesystemPathsRejected tests that two rules targeting
// the same normalized path are rejected.
func TestE2E_ConfiguringExecave_DuplicateFilesystemPathsRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:ro:/home/user", "fs:rw:/home/user")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("duplicate path")
	s.thenStderrContains("/home/user")
}

// TestE2E_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected tests that two net rules
// with the same target and port but different actions are rejected.
func TestE2E_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRules("net:http:example.com:443", "net:none:example.com:443")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("duplicate net rule")
}

// TestE2E_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected tests that a wildcard port
// and a specific port on the same target are rejected.
func TestE2E_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRules("net:http:example.com:*", "net:none:example.com:443")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("mixed port patterns")
}

// TestE2E_ConfiguringExecave_ConfigFileExplicitlyWritableRejected tests that a rule granting
// rw access to the config file itself is rejected.
func TestE2E_ConfiguringExecave_ConfigFileExplicitlyWritableRejected(t *testing.T) {
	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.toml")

	configContent := `fs = ["rw:` + configPath + `"]`
	err := os.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "config file must not be writable")
}

// TestE2E_ConfiguringExecave_ManagedPathsInRulesRejected tests that rules targeting managed
// paths (/dev, /proc, /tmp, auto-detected ELF interpreter) or their descendants are rejected.
func TestE2E_ConfiguringExecave_ManagedPathsInRulesRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:ro:/proc/self/status")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("managed path")
}

// TestE2E_ConfiguringExecave_TildeRuleExpandsAndMountsCorrectly tests that a tilde
// path in a rule is expanded to the home directory and the path is mounted correctly.
func TestE2E_ConfiguringExecave_TildeRuleExpandsAndMountsCorrectly(t *testing.T) {
	s := newScenario(t)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	data := s.givenDir("data")
	dataFile := data.file("data.txt", "tilde content")

	rel, err := filepath.Rel(homeDir, data.String())
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(rel))

	tildeDir := "~/" + rel
	s.givenRules("fs:ro:" + tildeDir)

	s.whenRun("cat", dataFile)

	s.thenExitCode(0)
	s.thenStdoutContains("tilde content")
}

// TestE2E_ConfiguringExecave_TildeDuplicatePathRejected tests that two tilde rules
// that expand to the same absolute path are rejected with a duplicate path error.
func TestE2E_ConfiguringExecave_TildeDuplicatePathRejected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tmpDir := testTempDir(t)
	rel, err := filepath.Rel(homeDir, tmpDir)
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(rel))

	tildeDir := "~/" + rel
	rules := []string{
		"fs:ro:" + tildeDir,
		"fs:rw:" + tmpDir,
	}

	result := runExecave(t, "", "--config", writeConfig(t, rules), "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "duplicate path")
	assert.Contains(t, result.Stderr, tmpDir)
}

// TestE2E_ConfiguringExecave_CommentsInConfig tests that TOML comments in the config
// file are ignored and the config loads successfully.
func TestE2E_ConfiguringExecave_CommentsInConfig(t *testing.T) {
	s := newScenario(t)
	s.givenRawConfig(`# Sandbox config
fs = [
    # System libraries
    "ro:/usr",
    "ro:/lib",
    "ro:/lib64",
    "ro:/etc/ld.so.cache",  # linker cache
]`)

	s.whenRun("echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

// TestE2E_ConfiguringExecave_SelectivelyAllowABlockedSyscall tests that syscall:allow
// permits a specific blocked syscall, which then returns a kernel error (not EPERM from seccomp).
func TestE2E_ConfiguringExecave_SelectivelyAllowABlockedSyscall(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules("syscall:allow:bpf")

	// With syscall:allow:bpf the seccomp filter passes bpf through; the kernel returns EINVAL
	// (invalid args), not EPERM (which would indicate seccomp denial).
	s.whenRun("python3", "-c",
		"import ctypes,ctypes.util;lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);lib.syscall(321,0,0,0);print(ctypes.get_errno())")

	s.thenExitCode(0)
	s.thenStdoutContains("22") // EINVAL, not 1 (EPERM from seccomp)
}

// TestE2E_ConfiguringExecave_InvalidSyscallNameRejectedAtConfigParse tests that a misspelled
// syscall name in a syscall:allow rule causes execave to exit with an error.
func TestE2E_ConfiguringExecave_InvalidSyscallNameRejectedAtConfigParse(t *testing.T) {
	result := runExecave(t, "", "--config", writeConfig(t, []string{"syscall:allow:ptraec"}), "--", "ls")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "ptraec")
}

// TestE2E_ConfiguringExecave_DefenseInDepthSyscallRejectedAtConfigParse tests that a syscall
// already blocked by the kernel inside the sandbox (defense-in-depth) is rejected at parse time.
func TestE2E_ConfiguringExecave_DefenseInDepthSyscallRejectedAtConfigParse(t *testing.T) {
	result := runExecave(t, "", "--config", writeConfig(t, []string{"syscall:allow:syslog"}), "--", "ls")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "syslog")
}

// TestE2E_ConfiguringExecave_MultipleSyscallRules tests that multiple syscall:allow rules
// can coexist and each permitted syscall appears as OK in the access log.
func TestE2E_ConfiguringExecave_MultipleSyscallRules(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules("syscall:allow:bpf", "syscall:allow:reboot")

	// Invoke both syscalls; reboot uses invalid magic (0,0,0) so it returns EINVAL, not actually rebooting.
	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "python3", "-c", bpfRebootPythonCmd)

	s.thenStderrHasEntry("SYSCALL", "bpf", "OK", "syscall:allow:bpf")
	s.thenStderrHasEntry("SYSCALL", "reboot", "OK", "syscall:allow:reboot")
}

// TestE2E_ConfiguringExecave_DuplicateSyscallAllowRulesRejected tests that duplicate
// syscall:allow rules are rejected with an error at config parse time.
func TestE2E_ConfiguringExecave_DuplicateSyscallAllowRulesRejected(t *testing.T) {
	rules := []string{"syscall:allow:ptrace", "syscall:allow:ptrace"}
	result := runExecave(t, "", "--config", writeConfig(t, rules), "--", "ls")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "duplicate")
}

// TestE2E_ConfiguringExecave_DuplicateSyscallNologRulesRejected tests that duplicate
// syscall:nolog rules are rejected with an error at config parse time.
func TestE2E_ConfiguringExecave_DuplicateSyscallNologRulesRejected(t *testing.T) {
	rules := []string{"syscall:nolog:ptrace", "syscall:nolog:ptrace"}
	result := runExecave(t, "", "--config", writeConfig(t, rules), "--", "ls")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "duplicate")
}

// requireRoot skips the test if not running as root, since creating root-owned
// test fixtures requires root. Version check tests use root-owned fake bwrap/strace
// wrappers to verify execave's version compatibility enforcement.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root to create root-owned test fixtures (re-run as root)")
	}
}

// fakeVersionWrapper writes a shell script in dir/name that:
//   - prints versionLine when called with --version
//   - delegates to realBin for all other invocations
//
// The script is made root-owned (requires root), so ValidateBinary accepts it.
func fakeVersionWrapper(t *testing.T, dir, name, versionLine, realBin string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	content := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then\n" +
		"  echo '" + versionLine + "'\n" +
		"else\n" +
		"  exec " + realBin + " \"$@\"\n" +
		"fi\n"
	require.NoError(t, os.WriteFile(p, []byte(content), 0o755)) // #nosec G306 -- test script needs execute permission
	require.NoError(t, os.Chown(p, 0, 0))
	return p
}

// TestE2E_ConfiguringExecave_IncompatibleBwrapVersionBlocksExecution tests that execave
// exits with an error and prints a message when bwrap is at an incompatible version.
func TestE2E_ConfiguringExecave_IncompatibleBwrapVersionBlocksExecution(t *testing.T) {
	requireRoot(t)

	realBwrap, err := findRealBwrap(t)
	require.NoError(t, err)

	fakeDir := testTempDir(t)
	fakeVersionWrapper(t, fakeDir, "bwrap", "bwrap 0.10.0", realBwrap)

	s := &scenario{t: t, tmpDir: testTempDir(t)}
	s.givenRules()
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("incompatible")
}

// TestE2E_ConfiguringExecave_IncompatibleStraceVersionBlocksMonitoring tests that execave
// exits with an error and prints a message when strace is at an incompatible version.
func TestE2E_ConfiguringExecave_IncompatibleStraceVersionBlocksMonitoring(t *testing.T) {
	requireRoot(t)
	failIfNoStrace(t)

	realStrace, err := findRealStrace(t)
	require.NoError(t, err)

	fakeDir := testTempDir(t)
	fakeVersionWrapper(t, fakeDir, "strace", "strace -- version 6.17", realStrace)

	s := &scenario{t: t, tmpDir: testTempDir(t)}
	s.givenRules()
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	s.whenRunTextLog("-", "true")

	s.thenExitCode(1)
	s.thenStderrContains("incompatible")
}

// TestE2E_ConfiguringExecave_NewerMinorBwrapPrintsWarningButContinues tests that execave
// prints a warning but runs the command normally when bwrap is at a warn-tier version.
func TestE2E_ConfiguringExecave_NewerMinorBwrapPrintsWarningButContinues(t *testing.T) {
	requireRoot(t)

	realBwrap, err := findRealBwrap(t)
	require.NoError(t, err)

	fakeDir := testTempDir(t)
	fakeVersionWrapper(t, fakeDir, "bwrap", "bwrap 0.12.0", realBwrap)

	s := &scenario{t: t, tmpDir: testTempDir(t)}
	s.givenRules()
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	s.whenRun("echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
	s.thenStderrContains("warning")
}

// TestE2E_ConfiguringExecave_NewerMinorStracePrintsWarningButContinues tests that execave
// prints a warning but continues monitoring when strace is at a warn-tier version.
func TestE2E_ConfiguringExecave_NewerMinorStracePrintsWarningButContinues(t *testing.T) {
	requireRoot(t)
	failIfNoStrace(t)

	realStrace, err := findRealStrace(t)
	require.NoError(t, err)

	fakeDir := testTempDir(t)
	fakeVersionWrapper(t, fakeDir, "strace", "strace -- version 6.19", realStrace)

	s := &scenario{t: t, tmpDir: testTempDir(t)}
	s.givenRules()
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	s.whenRunTextLog("-", "echo", "hello")

	s.thenExitCode(0)
	s.thenStderrContains("warning")
}

// findRealBwrap returns the path to the real (root-owned) bwrap binary.
func findRealBwrap(t *testing.T) (string, error) {
	t.Helper()
	failIfNoBwrap(t)

	info, err := os.Stat("/usr/bin/bwrap")
	if err == nil && !info.IsDir() {
		return "/usr/bin/bwrap", nil
	}
	info, err = os.Stat("/usr/local/bin/bwrap")
	if err == nil && !info.IsDir() {
		return "/usr/local/bin/bwrap", nil
	}
	return "", os.ErrNotExist
}

// findRealStrace returns the path to the real (root-owned) strace binary.
func findRealStrace(t *testing.T) (string, error) {
	t.Helper()
	failIfNoStrace(t)

	info, err := os.Stat("/usr/bin/strace")
	if err == nil && !info.IsDir() {
		return "/usr/bin/strace", nil
	}
	info, err = os.Stat("/usr/local/bin/strace")
	if err == nil && !info.IsDir() {
		return "/usr/local/bin/strace", nil
	}
	return "", os.ErrNotExist
}
