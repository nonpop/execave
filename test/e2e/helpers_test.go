package e2e_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	TmpDir string
}

// newMonitorTest creates a test environment for monitor tests.
// It fails if bwrap or strace are not available.
func newMonitorTest(t *testing.T) monitorTestEnv {
	t.Helper()
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	return monitorTestEnv{
		TmpDir: tmpDir,
	}
}

// monitoredResult contains the result of a monitored execave run,
// including the web UI HTML content for entry assertions.
type monitoredResult struct {
	execaveResult

	WebUI      string
	MonitorURL string
}

// runMonitored runs execave with monitoring enabled using the given rules and command args.
// It starts the process in the background, waits for the sandbox command to finish,
// fetches entries from the web UI, then sends SIGINT to stop the monitor.
func (env monitorTestEnv) runMonitored(t *testing.T, rules []string, args ...string) monitoredResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	execArgs := make([]string, 0, 4+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor=0", "--")
	execArgs = append(execArgs, args...)
	return runExecaveMonitored(t, execArgs...)
}

// runMonitoredWithInterrupt runs execave with monitoring enabled and sends SIGINT
// to the process group after a short delay, simulating terminal ctrl-c behavior.
// It fetches web UI entries before sending SIGINT.
func (env monitorTestEnv) runMonitoredWithInterrupt(t *testing.T, rules []string, args ...string) monitoredResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	execArgs := make([]string, 0, 4+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor=0", "--")
	execArgs = append(execArgs, args...)
	return runMonitoredCmd(t, monitorRunOpts{
		readyLine:     "execave: monitor running at ",
		preFetchDelay: 200 * time.Millisecond,
	}, execArgs...)
}

// monitorRunOpts configures how runMonitoredCmd determines readiness.
type monitorRunOpts struct {
	// readyLine is a stderr substring that signals when to fetch the web UI.
	readyLine string
	// preFetchDelay is an optional delay before fetching the web UI after readiness.
	preFetchDelay time.Duration
}

// runMonitoredCmd starts execave with monitoring in the background, waits for
// readyLine in stderr, fetches the web UI, sends SIGINT, and returns the result.
func runMonitoredCmd(t *testing.T, opts monitorRunOpts, args ...string) monitoredResult {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), binaryPath, args...) // #nosec G204 -- test code with controlled args
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdout strings.Builder
	cmd.Stdout = &stdout

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())

	// Read stderr in goroutine, extract monitor URL and signal readiness
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
			if strings.Contains(line, opts.readyLine) {
				stderrOnce.Do(func() { close(stderrReady) })
			}
		}
		stderrOnce.Do(func() { close(stderrReady) })
		stderrDone <- sb.String()
	}()

	// Wait for readiness
	<-stderrReady
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	if opts.preFetchDelay > 0 {
		time.Sleep(opts.preFetchDelay)
	}

	// Fetch entries from web UI
	webUI := fetchWebUI(t, monitorURL)
	// Send SIGINT to stop the monitor
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	// Wait for process to exit
	waitErr := cmd.Wait()
	result := execaveResult{
		Stdout:   stdout.String(),
		Stderr:   <-stderrDone,
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

	return monitoredResult{execaveResult: result, WebUI: webUI, MonitorURL: monitorURL}
}

// runExecaveMonitored starts execave with monitoring in the background, waits for the
// sandbox command to finish, fetches the web UI, sends SIGINT, and returns the result.
func runExecaveMonitored(t *testing.T, args ...string) monitoredResult {
	t.Helper()
	return runMonitoredCmd(t, monitorRunOpts{readyLine: "Press Ctrl-C", preFetchDelay: 0}, args...)
}

// fetchWebUI fetches the HTML content from the web UI at the given base URL.
func fetchWebUI(t *testing.T, baseURL string) string {
	t.Helper()
	resp, err := http.Get(baseURL + "/") // #nosec G107 -- test code with controlled URL
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// assertWebUIHasEntry checks that the web UI HTML response contains a table row
// (<tr>...</tr>) with all given substrings.
func assertWebUIHasEntry(t *testing.T, webUI string, substrings ...string) {
	t.Helper()

	rows := parseTableRows(webUI)
	for _, row := range rows {
		if rowContainsAll(row, substrings) {
			return
		}
	}
	t.Errorf("web UI has no single row containing all of %q", substrings)
}

// parseTableRows extracts the content between each <tr>...</tr> pair in the HTML.
func parseTableRows(html string) []string {
	var rows []string
	rest := html
	for {
		start := strings.Index(rest, "<tr>")
		if start == -1 {
			break
		}
		end := strings.Index(rest[start:], "</tr>")
		if end == -1 {
			break
		}
		rows = append(rows, rest[start:start+end+len("</tr>")])
		rest = rest[start+end+len("</tr>"):]
	}
	return rows
}

// rowContainsAll reports whether row contains every one of the given substrings.
func rowContainsAll(row string, substrings []string) bool {
	for _, s := range substrings {
		if !strings.Contains(row, s) {
			return false
		}
	}
	return true
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
