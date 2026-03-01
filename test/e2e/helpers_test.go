package e2e_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func failIfNoCurl(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("curl")
	require.NoError(t, err)
}

func failIfNoPython3(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("python3")
	require.NoError(t, err)
}

func failIfNoGcc(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("gcc")
	require.NoError(t, err)
}

// tomlConfig formats rules as a TOML config file.
// Rules are grouped by prefix and emitted as flat key sections (fs, net, syscall).
func tomlConfig(rules []string) []byte {
	// Group rules by prefix
	fsRules := []string{}
	netRules := []string{}
	syscallRules := []string{}

	for _, r := range rules {
		if strings.HasPrefix(r, "fs:") {
			fsRules = append(fsRules, strings.TrimPrefix(r, "fs:"))
		} else if strings.HasPrefix(r, "net:") {
			netRules = append(netRules, strings.TrimPrefix(r, "net:"))
		} else if strings.HasPrefix(r, "syscall:") {
			syscallRules = append(syscallRules, strings.TrimPrefix(r, "syscall:"))
		}
	}

	var sb strings.Builder

	// Emit fs section if there are fs rules
	if len(fsRules) > 0 {
		sb.WriteString("fs = [\n")
		for _, r := range fsRules {
			fmt.Fprintf(&sb, "    %q,\n", r)
		}
		sb.WriteString("]\n")
	}

	// Emit net section if there are net rules
	if len(netRules) > 0 {
		sb.WriteString("net = [\n")
		for _, r := range netRules {
			fmt.Fprintf(&sb, "    %q,\n", r)
		}
		sb.WriteString("]\n")
	}

	// Emit syscall section if there are syscall rules
	if len(syscallRules) > 0 {
		sb.WriteString("syscall = [\n")
		for _, r := range syscallRules {
			fmt.Fprintf(&sb, "    %q,\n", r)
		}
		sb.WriteString("]\n")
	}

	return []byte(sb.String())
}

func writeConfig(t *testing.T, rules []string) string {
	t.Helper()
	dir := testTempDir(t)
	configPath := filepath.Join(dir, "execave.toml")

	err := os.WriteFile(configPath, tomlConfig(rules), 0o600)
	require.NoError(t, err)

	return configPath
}

func writeConfigInDir(t *testing.T, dir string, rules []string) {
	t.Helper()
	configPath := filepath.Join(dir, "execave.toml")

	err := os.WriteFile(configPath, tomlConfig(rules), 0o600)
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

// systemPaths returns rules for basic command execution.
func systemPaths() []string {
	return []string{
		"fs:ro:/usr",
		"fs:ro:/lib",
		"fs:ro:/lib64",
		"fs:ro:/etc/ld.so.cache",
	}
}

// testDir is a named string type representing a directory path with convenience methods
// for test file management and path manipulation.
type testDir string

// String returns the raw directory path.
func (d testDir) String() string {
	return string(d)
}

// join constructs a path by joining parts under this directory.
func (d testDir) join(parts ...string) string {
	return filepath.Join(append([]string{string(d)}, parts...)...)
}

// file creates a file with the given content under this directory,
// creating parent directories as needed.
func (d testDir) file(name, content string) string {
	path := d.join(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		panic("testDir.file: mkdir: " + err.Error())
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		panic("testDir.file: write: " + err.Error())
	}
	return path
}

// rel returns the ~/‑shortened form of a path under this directory,
// suitable for monitor log assertions.
func (d testDir) rel(sub string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic("testDir.rel: UserHomeDir: " + err.Error())
	}
	full := d.join(sub)
	r, err := filepath.Rel(homeDir, full)
	if err != nil {
		panic("testDir.rel: Rel: " + err.Error())
	}
	return "~/" + r
}

// testServer wraps a test HTTP/HTTPS server with convenience accessors.
type testServer struct {
	host string
	port string
}

// hostPort returns "host:port" joined with net.JoinHostPort.
func (s testServer) hostPort() string {
	return net.JoinHostPort(s.host, s.port)
}

// addr returns "host:port" in the rule format (colon-separated, no brackets).
func (s testServer) addr() string {
	return s.host + ":" + s.port
}

// scenario is a unified test harness for E2E tests that encapsulates temp dir creation,
// config writing, binary execution, and result assertions.
type scenario struct {
	t          *testing.T
	tmpDir     string
	configPath string
	configDir  string
	lastResult *execaveResult
}

// newScenario creates a new scenario, failing if bwrap is not available.
func newScenario(t *testing.T) *scenario {
	t.Helper()
	failIfNoBwrap(t)
	return &scenario{
		t:          t,
		tmpDir:     testTempDir(t),
		configPath: "",
		configDir:  "",
		lastResult: nil,
	}
}

// givenDir creates a named subdirectory under the scenario's temp dir
// and returns it as a testDir.
func (s *scenario) givenDir(name string) testDir {
	s.t.Helper()
	d := filepath.Join(s.tmpDir, name)
	err := os.MkdirAll(d, 0o750)
	require.NoError(s.t, err)
	return testDir(d)
}

// givenSymlink creates a symlink at link pointing to target,
// creating parent directories as needed.
func (s *scenario) givenSymlink(target, link string) {
	s.t.Helper()
	createSymlink(s.t, target, link)
}

// givenRules sets the scenario's config by prepending systemPaths() to the given rules
// and writing a config file.
func (s *scenario) givenRules(rules ...string) {
	s.t.Helper()
	allRules := append(systemPaths(), rules...)
	s.configPath = writeConfig(s.t, allRules)
	s.configDir = filepath.Dir(s.configPath)
}

// givenRulesOnly sets the scenario's config to exactly the given rules,
// without prepending systemPaths(). Use for error-path tests.
func (s *scenario) givenRulesOnly(rules ...string) {
	s.t.Helper()
	s.configPath = writeConfig(s.t, rules)
	s.configDir = filepath.Dir(s.configPath)
}

// givenRulesInDir writes the config in a specific directory and uses that as config dir.
// Rules are prepended with systemPaths().
func (s *scenario) givenRulesInDir(dir string, rules ...string) {
	s.t.Helper()
	allRules := append(systemPaths(), rules...)
	writeConfigInDir(s.t, dir, allRules)
	s.configPath = filepath.Join(dir, "execave.toml")
	s.configDir = dir
}

// givenRawConfig writes raw config content (not rules array) to a config file.
func (s *scenario) givenRawConfig(content string) {
	s.t.Helper()
	dir := testTempDir(s.t)
	configPath := filepath.Join(dir, "execave.toml")
	err := os.WriteFile(configPath, []byte(content), 0o600)
	require.NoError(s.t, err)
	s.configPath = configPath
	s.configDir = dir
}

// whenRun executes execave with the scenario's config and the given command args.
// Resets the last result but keeps the config.
func (s *scenario) whenRun(args ...string) {
	s.t.Helper()
	execArgs := make([]string, 0, 4+len(args))
	if s.configPath != "" {
		execArgs = append(execArgs, "--config", s.configPath)
	}
	execArgs = append(execArgs, "--")
	execArgs = append(execArgs, args...)
	result := runExecave(s.t, "", execArgs...)
	s.lastResult = &result
}

// whenRunWithDefaultConfig executes execave without --config, relying on default config location.
func (s *scenario) whenRunWithDefaultConfig(workDir string, args ...string) {
	s.t.Helper()
	execArgs := append([]string{"--"}, args...)
	result := runExecave(s.t, workDir, execArgs...)
	s.lastResult = &result
}

// whenRunTextLog executes execave with --monitor=<monitorArg> for text log tests.
func (s *scenario) whenRunTextLog(monitorArg string, args ...string) {
	s.t.Helper()
	failIfNoStrace(s.t)
	execArgs := make([]string, 0, 5+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--monitor="+monitorArg, "--")
	execArgs = append(execArgs, args...)
	result := runExecave(s.t, "", execArgs...)
	s.lastResult = &result
}

// whenRunTextLogWithFlags executes execave with --monitor=- and extra flags.
func (s *scenario) whenRunTextLogWithFlags(flags []string, args ...string) {
	s.t.Helper()
	failIfNoStrace(s.t)
	execArgs := make([]string, 0, 5+len(flags)+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--monitor=-")
	execArgs = append(execArgs, flags...)
	execArgs = append(execArgs, "--")
	execArgs = append(execArgs, args...)
	result := runExecave(s.t, "", execArgs...)
	s.lastResult = &result
}

// whenRunNoSandbox executes execave with --no-sandbox but without --monitor.
func (s *scenario) whenRunNoSandbox(args ...string) {
	s.t.Helper()
	execArgs := make([]string, 0, 4+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--no-sandbox", "--")
	execArgs = append(execArgs, args...)
	result := runExecave(s.t, "", execArgs...)
	s.lastResult = &result
}

// whenRunNoSandboxMonitorFile executes execave with --no-sandbox --monitor=<file>.
func (s *scenario) whenRunNoSandboxMonitorFile(monitorFile string, args ...string) {
	s.t.Helper()
	execArgs := make([]string, 0, 5+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--no-sandbox", "--monitor="+monitorFile, "--")
	execArgs = append(execArgs, args...)
	result := runExecave(s.t, "", execArgs...)
	s.lastResult = &result
}

// givenCurl fails the test if curl is not available.
func (s *scenario) givenCurl() {
	s.t.Helper()
	failIfNoCurl(s.t)
}

// givenPython3 fails the test if python3 is not available.
func (s *scenario) givenPython3() {
	s.t.Helper()
	failIfNoPython3(s.t)
}

// givenGcc fails the test if gcc is not available.
func (s *scenario) givenGcc() {
	s.t.Helper()
	failIfNoGcc(s.t)
}

// thenExitCode asserts the last run's exit code equals n.
func (s *scenario) thenExitCode(n int) {
	s.t.Helper()
	require.NotNil(s.t, s.lastResult)
	assertExitCode(s.t, *s.lastResult, n)
}

// thenExitCodeNonZero asserts the last run's exit code is not zero.
func (s *scenario) thenExitCodeNonZero() {
	s.t.Helper()
	require.NotNil(s.t, s.lastResult)
	assert.NotEqual(s.t, 0, s.lastResult.ExitCode)
}

// thenStdoutContains asserts the last run's stdout contains sub.
func (s *scenario) thenStdoutContains(sub string) {
	s.t.Helper()
	require.NotNil(s.t, s.lastResult)
	assert.Contains(s.t, s.lastResult.Stdout, sub)
}

// thenStderrContains asserts the last run's stderr contains sub.
func (s *scenario) thenStderrContains(sub string) {
	s.t.Helper()
	require.NotNil(s.t, s.lastResult)
	assert.Contains(s.t, s.lastResult.Stderr, sub)
}

// thenStderrNotContains asserts the last run's stderr does not contain sub.
func (s *scenario) thenStderrNotContains(sub string) {
	s.t.Helper()
	require.NotNil(s.t, s.lastResult)
	assert.NotContains(s.t, s.lastResult.Stderr, sub)
}

// thenStderrHasEntry asserts that a single stderr line contains all given substrings.
func (s *scenario) thenStderrHasEntry(substrings ...string) {
	s.t.Helper()
	require.NotNil(s.t, s.lastResult)
	scanner := bufio.NewScanner(strings.NewReader(s.lastResult.Stderr))
	for scanner.Scan() {
		line := scanner.Text()
		found := true
		for _, sub := range substrings {
			if !strings.Contains(line, sub) {
				found = false
				break
			}
		}
		if found {
			return
		}
	}
	s.t.Errorf("stderr has no single line containing all of %q\nstderr:\n%s", substrings, s.lastResult.Stderr)
}

// thenFileContains asserts that the file at path exists and contains sub.
func (s *scenario) thenFileContains(path, sub string) {
	s.t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test code reading controlled test files
	require.NoError(s.t, err)
	assert.Contains(s.t, string(data), sub)
}

// givenHTTPServer starts a plain HTTP test server returning body.
func (s *scenario) givenHTTPServer(body string) testServer {
	s.t.Helper()
	h, p := testHTTPServer(s.t, body)
	return testServer{host: h, port: p}
}

// givenHTTPSServer starts a TLS HTTP test server returning body.
func (s *scenario) givenHTTPSServer(body string) testServer {
	s.t.Helper()
	h, p := testHTTPSServer(s.t, body)
	return testServer{host: h, port: p}
}

// testHTTPServer starts a plain HTTP server that returns body.
// Returns the listener host and port.
func testHTTPServer(t *testing.T, body string) (string, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	h, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return h, p
}

// testHTTPSServer starts a TLS HTTP server that returns body.
// Returns the listener host and port.
func testHTTPSServer(t *testing.T, body string) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	h, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return h, p
}
