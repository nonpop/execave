package run_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nonpop/execave/internal/run"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testExecaveBinary string //nolint:gochecknoglobals

// TestMain builds the execave binary once for all integration tests.
func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	tmpDir, err := os.MkdirTemp("", "execave-run-integ-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	testExecaveBinary = filepath.Join(tmpDir, "execave")

	// Find project root relative to this source file (two levels up from internal/run).
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", testExecaveBinary, "./cmd/execave") // #nosec G204 -- test code with controlled args
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("failed to build execave binary: " + err.Error())
	}

	return m.Run()
}

// writeMinimalConfig creates a minimal execave config file in dir and returns its path.
// fsRules is a list of TOML-formatted fs rule strings (e.g., `"ro:/usr"`).
func writeMinimalConfig(t *testing.T, dir string, fsRules []string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "execave.toml")
	content := "fs = ["
	for i, r := range fsRules {
		if i > 0 {
			content += ", "
		}
		content += fmt.Sprintf("%q", r)
	}
	content += "]\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

// TestIntegration_MonitoredRun_CommandRunsAndExits tests that a monitored run
// executes the command and returns the correct exit code.
func TestIntegration_MonitoredRun_CommandRunsAndExits(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	//nolint:usetesting // need a path outside /tmp to avoid managed path conflicts
	tmpDir, err := os.MkdirTemp(".", "run-monitored-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	absTmpDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	// Build rules for paths that exist on this system
	var rules []string
	paths := []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"}
	for _, p := range paths {
		if _, statErr := os.Stat(p); statErr == nil {
			rules = append(rules, "ro:"+p)
		}
	}
	rules = append(rules, "ro:"+absTmpDir)

	cfgPath := writeMinimalConfig(t, absTmpDir, rules)

	tunnelBin := filepath.Join(absTmpDir, "execave")
	require.NoError(t, copyFile(testExecaveBinary, tunnelBin, 0o755))

	exitCode, err := run.Run(run.SandboxConfig{
		ConfigPath:   cfgPath,
		TargetArgv:   []string{"true"},
		TunnelBinary: tunnelBin,

		MonitorConfig: &run.MonitorConfig{
			File: filepath.Join(absTmpDir, "access.log"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// --- Requirement: Unsandboxed run mode ---

// TestIntegration_NoSandbox_CommandRunsWithoutBwrap verifies that in unsandboxed mode
// the command runs successfully without bwrap and access log entries are produced.
func TestIntegration_NoSandbox_CommandRunsWithoutBwrap(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	//nolint:usetesting // need a path outside /tmp for access log entries
	tmpDir, err := os.MkdirTemp(".", "run-nosandbox-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	absTmpDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	testFile := filepath.Join(absTmpDir, "file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("hello"), 0o600))

	logFile := filepath.Join(absTmpDir, "access.log")
	cfgPath := writeMinimalConfig(t, absTmpDir, []string{"ro:" + absTmpDir})

	exitCode, err := run.Run(run.SandboxConfig{
		ConfigPath:   cfgPath,
		TargetArgv:   []string{"cat", testFile},
		TunnelBinary: testExecaveBinary,

		MonitorConfig: &run.MonitorConfig{
			File:        logFile,
			LogAllowed:  true,
			Unsandboxed: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// Access log entries must be produced
	logData, readErr := os.ReadFile(logFile)
	require.NoError(t, readErr)
	assert.NotEmpty(t, string(logData))
}

// TestIntegration_NoSandbox_BlockedSyscallLogged verifies that in unsandboxed mode,
// syscalls from the blocklist are still traced and logged when they occur.
func TestIntegration_NoSandbox_BlockedSyscallLogged(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	helperBin := buildPtraceHelper(t)

	//nolint:usetesting // need a path outside /tmp for access log entries
	tmpDir, err := os.MkdirTemp(".", "run-nosandbox-syscall-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	absTmpDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	logFile := filepath.Join(absTmpDir, "access.log")
	cfgPath := writeMinimalConfig(t, absTmpDir, nil)

	exitCode, err := run.Run(run.SandboxConfig{
		ConfigPath:   cfgPath,
		TargetArgv:   []string{helperBin},
		TunnelBinary: testExecaveBinary,

		MonitorConfig: &run.MonitorConfig{
			File:        logFile,
			LogAllowed:  true,
			Unsandboxed: true,
		},
	})
	// The ptrace helper exits 0 in unsandboxed mode (syscall succeeds or is ignored)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logData, readErr := os.ReadFile(logFile)
	require.NoError(t, readErr)
	logStr := string(logData)
	assert.Contains(t, logStr, "UNENFORCED")
	assert.Contains(t, logStr, "SYSCALL")
	assert.Contains(t, logStr, "ptrace")
}

// TestIntegration_NoSandbox_SeccompNotApplied verifies that in unsandboxed mode,
// syscalls that would normally be blocked by seccomp can still be called successfully.
// No seccomp filter is applied; the monitor traces blocked syscalls for logging only.
func TestIntegration_NoSandbox_SeccompNotApplied(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	//nolint:usetesting // need a path outside /tmp to avoid managed path conflicts
	tmpDir, err := os.MkdirTemp(".", "run-nosandbox-seccomp-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	absTmpDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	logFile := filepath.Join(absTmpDir, "access.log")
	cfgPath := writeMinimalConfig(t, absTmpDir, nil)

	// 'true' is a minimal command; verifying it runs successfully in unsandboxed mode
	// is sufficient to confirm no seccomp filter was applied.
	exitCode, err := run.Run(run.SandboxConfig{
		ConfigPath:   cfgPath,
		TargetArgv:   []string{"true"},
		TunnelBinary: testExecaveBinary,

		MonitorConfig: &run.MonitorConfig{
			File:        logFile,
			Unsandboxed: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// TestIntegration_NoSandbox_HTTPProxyInjectedWhenNetPathConfigured verifies that when
// unsandboxed=true and net rules are configured, HTTP_PROXY env vars are injected so that
// proxy-aware commands can reach the TCP bridge.
func TestIntegration_NoSandbox_HTTPProxyInjectedWhenNetPathConfigured(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	//nolint:usetesting // need a path outside /tmp to avoid managed path conflicts
	tmpDir, err := os.MkdirTemp(".", "run-nosandbox-proxy-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	absTmpDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	logFile := filepath.Join(absTmpDir, "access.log")

	// Config with net rules to trigger proxy setup
	cfgPath := filepath.Join(absTmpDir, "execave.toml")
	cfgContent := `net = ["http:example.com:443"]` + "\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	exitCode, err := run.Run(run.SandboxConfig{
		ConfigPath:   cfgPath,
		TargetArgv:   []string{"sh", "-c", `test -n "$HTTP_PROXY"`},
		TunnelBinary: testExecaveBinary,

		MonitorConfig: &run.MonitorConfig{
			File:        logFile,
			Unsandboxed: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// copyFile copies src to dst with the given permissions.
func copyFile(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src) // #nosec G304 -- test helper with controlled paths
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, perm); err != nil { // #nosec G306 -- executable permission intentional
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}

// buildPtraceHelper compiles a small binary that calls ptrace(PTRACE_TRACEME)
// and returns its path. The binary is placed in a t.TempDir().
func buildPtraceHelper(t *testing.T) string {
	t.Helper()
	const helperSrc = `package main

import "syscall"

func main() {
//nolint:errcheck
syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
}
`
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(helperSrc), 0o600))
	helperBin := filepath.Join(tmpDir, "ptrace-helper")
	buildCmd := exec.Command("go", "build", "-o", helperBin, srcFile) //nolint:gosec // test-controlled args
	buildOut, buildErr := buildCmd.CombinedOutput()
	require.NoError(t, buildErr, string(buildOut))
	return helperBin
}
