package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testTempDir creates a temporary directory for tests in a location that's not
// managed by the sandbox. Unlike t.TempDir() which uses /tmp (a managed path),
// this creates directories under the project root in .test-tmp/.
func testTempDir(t *testing.T) string {
	t.Helper()

	// Find project root (go up from test/e2e to project root)
	projectRoot, err := filepath.Abs("../..")
	require.NoError(t, err)

	// Create base test-tmp directory
	baseTmpDir := filepath.Join(projectRoot, ".test-tmp")
	err = os.MkdirAll(baseTmpDir, 0o750)
	require.NoError(t, err)

	// Create unique subdirectory for this test
	//nolint:usetesting // intentionally not using t.TempDir() - we need a custom location
	tmpDir, err := os.MkdirTemp(baseTmpDir, t.Name())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.RemoveAll(tmpDir)
	})

	return tmpDir
}

func failIfNoBwrap(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("bwrap")
	require.NoError(t, err)
}

func failIfNoStrace(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("strace")
	require.NoError(t, err)
}

type configJSON struct {
	Rules []string `json:"rules"`
}

func writeConfig(t *testing.T, rules []string) string {
	t.Helper()
	dir := testTempDir(t)
	configPath := filepath.Join(dir, "execave.json")

	cfg := configJSON{Rules: rules}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	err = os.WriteFile(configPath, data, 0o600)
	require.NoError(t, err)

	return configPath
}

func writeConfigInDir(t *testing.T, dir string, rules []string) {
	t.Helper()
	configPath := filepath.Join(dir, "execave.json")

	cfg := configJSON{Rules: rules}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	err = os.WriteFile(configPath, data, 0o600)
	require.NoError(t, err)
}

type execaveResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func runExecave(t *testing.T, workDir string, args ...string) execaveResult {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), binaryPath, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := execaveResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}

	if err != nil {
		exitErr := new(exec.ExitError)
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running execave: %v", err)
		}
	}

	return result
}

func assertExitCode(t *testing.T, result execaveResult, expected int) {
	t.Helper()
	if result.ExitCode != expected {
		t.Errorf("expected exit code %d, got %d\nstdout: %s\nstderr: %s",
			expected, result.ExitCode, result.Stdout, result.Stderr)
	}
}

func assertLogExists(t *testing.T, logPath string) {
	t.Helper()
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Errorf("expected log file to exist at %s", logPath)
	}
}

func assertLogNotExists(t *testing.T, logPath string) {
	t.Helper()
	if _, err := os.Stat(logPath); err == nil {
		t.Errorf("expected log file NOT to exist at %s", logPath)
	}
}

// assertLogLineContainsAll asserts that at least one line in the log file
// contains all of the given substrings.
func assertLogLineContainsAll(t *testing.T, logPath string, substrings ...string) {
	t.Helper()
	require.FileExists(t, logPath)
	data, err := os.ReadFile(logPath) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)

	for line := range strings.SplitSeq(string(data), "\n") {
		if lineContainsAll(line, substrings) {
			return
		}
	}

	t.Errorf("no single log line in %s contains all of %v\nlog contents:\n%s",
		logPath, substrings, string(data))
}

func lineContainsAll(line string, substrings []string) bool {
	for _, s := range substrings {
		if !strings.Contains(line, s) {
			return false
		}
	}
	return true
}

func createFile(t *testing.T, path, content string) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(path), 0o750)
	require.NoError(t, err)
	err = os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
}

func createSymlink(t *testing.T, target, link string) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(link), 0o750)
	require.NoError(t, err)
	err = os.Symlink(target, link)
	require.NoError(t, err)
}

// monitorTestEnv provides common setup for monitor e2e tests.
type monitorTestEnv struct {
	TmpDir  string
	LogPath string
}

// newMonitorTest creates a test environment for monitor tests.
// It fails if bwrap or strace are not available.
func newMonitorTest(t *testing.T) monitorTestEnv {
	t.Helper()
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	return monitorTestEnv{
		TmpDir:  tmpDir,
		LogPath: filepath.Join(tmpDir, "access.log"),
	}
}

// runMonitored runs execave with monitoring enabled using the given rules and command args.
func (env monitorTestEnv) runMonitored(t *testing.T, rules []string, args ...string) execaveResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	execArgs := make([]string, 0, 4+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor="+env.LogPath, "--")
	execArgs = append(execArgs, args...)
	return runExecave(t, "", execArgs...)
}

// runMonitoredWithInterrupt runs execave with monitoring enabled and sends SIGINT
// to the process group after a short delay, simulating terminal ctrl-c behavior.
func (env monitorTestEnv) runMonitoredWithInterrupt(t *testing.T, rules []string, args ...string) execaveResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	execArgs := make([]string, 0, 4+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor="+env.LogPath, "--")
	execArgs = append(execArgs, args...)

	cmd := exec.CommandContext(context.Background(), binaryPath, execArgs...) // #nosec G204 -- test code with controlled args

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Put execave in its own process group so we can send SIGINT to the entire
	// group (execave + strace + bwrap + child), mimicking terminal ctrl-c.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} //nolint:exhaustruct

	err := cmd.Start()
	require.NoError(t, err)

	// Give the process tree time to start
	time.Sleep(200 * time.Millisecond)

	// Send SIGINT to the process group (negative PID). This reaches all
	// processes in the group: execave (ignores it via signal.Notify),
	// strace, bwrap, and the child command.
	err = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	require.NoError(t, err)

	// Wait for the process to exit
	waitErr := cmd.Wait()

	result := execaveResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}

	if waitErr != nil {
		exitErr := new(exec.ExitError)
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error waiting for execave: %v", waitErr)
		}
	}

	return result
}

// readLog reads and returns the monitor log content.
func (env monitorTestEnv) readLog(t *testing.T) string {
	t.Helper()
	assertLogExists(t, env.LogPath)
	data, err := os.ReadFile(env.LogPath) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	return string(data)
}

// systemPaths returns rules for basic command execution.
func systemPaths() []string {
	return []string{
		"fs:ro:/usr",
		"fs:ro:/lib",
		"fs:ro:/lib64",
		"fs:ro:/etc/ld.so.cache",
	}
}
