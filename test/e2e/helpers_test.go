package e2e_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func failIfNoGcc(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("gcc")
	require.NoError(t, err)
}

// tomlConfig formats rules as a TOML config file.
func tomlConfig(rules []string) []byte {
	var sb strings.Builder
	sb.WriteString("rules = [\n")
	for _, r := range rules {
		fmt.Fprintf(&sb, "    %q,\n", r)
	}
	sb.WriteString("]\n")
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
	ConfigDir  string // directory of the config file used for this run
}

// runMonitored runs execave with monitoring enabled using the given rules and command args.
// It starts the process in the background, waits for the sandbox command to finish,
// fetches entries from the web UI, then sends SIGINT to stop the monitor.
func (env monitorTestEnv) runMonitored(t *testing.T, rules []string, args ...string) monitoredResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	configDir := filepath.Dir(configPath)
	execArgs := make([]string, 0, 5+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor", "--no-open", "--")
	execArgs = append(execArgs, args...)
	result := runExecaveMonitored(t, execArgs...)
	result.ConfigDir = configDir
	return result
}

// runMonitoredWithInterrupt runs execave with monitoring enabled and sends SIGINT
// to the process group after a short delay, simulating terminal ctrl-c behavior.
// It fetches web UI entries before sending SIGINT.
func (env monitorTestEnv) runMonitoredWithInterrupt(t *testing.T, rules []string, args ...string) monitoredResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	configDir := filepath.Dir(configPath)
	execArgs := make([]string, 0, 5+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor", "--no-open", "--")
	execArgs = append(execArgs, args...)
	result := runMonitoredCmd(t, monitorRunOpts{
		readyLine:     "execave: monitor running at ",
		preFetchDelay: 200 * time.Millisecond,
	}, execArgs...)
	result.ConfigDir = configDir
	return result
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

	return monitoredResult{execaveResult: result, WebUI: webUI, MonitorURL: monitorURL, ConfigDir: ""}
}

// runExecaveMonitored starts execave with monitoring in the background, waits for the
// monitor URL to appear, fetches the web UI after a short delay, sends SIGINT, and
// returns the result.
func runExecaveMonitored(t *testing.T, args ...string) monitoredResult {
	t.Helper()
	return runMonitoredCmd(t, monitorRunOpts{readyLine: "execave: monitor running at ", preFetchDelay: 200 * time.Millisecond}, args...)
}

// fetchWebUI fetches the HTML content from the web UI at the given monitor URL.
// monitorURL must be the full URL as returned by startMonitoredExecave (includes token).
func fetchWebUI(t *testing.T, monitorURL string) string {
	t.Helper()
	resp, err := http.Get(monitorURL) // #nosec G107 -- test code with controlled URL
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// monitorEndpoint constructs a token-bearing URL for the given path using the monitor
// URL returned by startMonitoredExecave (form: http://host:port?token=TOKEN).
func monitorEndpoint(monitorURL, path string) string {
	u, err := url.Parse(monitorURL)
	if err != nil {
		panic("invalid monitor URL: " + err.Error())
	}
	u.Path = path
	return u.String()
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

// parseTableRows extracts the content between each <tr...>...</tr> pair in the HTML.
// Handles both <tr> and <tr data-rule="..."> formats.
func parseTableRows(html string) []string {
	var rows []string
	rest := html
	for {
		start := strings.Index(rest, "<tr")
		if start == -1 {
			break
		}
		// Find the end of the opening tag
		tagEnd := strings.Index(rest[start:], ">")
		if tagEnd == -1 {
			break
		}
		// Find the closing tag
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

// sseEvent is a parsed Server-Sent Event for E2E test assertions.
type sseEvent struct {
	event string
	data  string
	id    string
}

// readSSEEvents reads up to n SSE events from the response body.
func readSSEEvents(resp *http.Response, n int) []sseEvent {
	scanner := bufio.NewScanner(resp.Body)
	var events []sseEvent
	var current sseEvent
	for len(events) < n && scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			current.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			current.data = strings.TrimPrefix(line, "data: ")
		case strings.HasPrefix(line, "id: "):
			current.id = strings.TrimPrefix(line, "id: ")
		case line == "":
			if current.event != "" || current.data != "" || current.id != "" {
				events = append(events, current)
				current = sseEvent{event: "", data: "", id: ""}
			}
		}
	}
	return events
}

// startMonitoredExecave starts execave with --monitor=0 and the given config,
// running the specified command. It waits for the monitor URL to appear on
// stderr and registers a cleanup that sends SIGINT to the process group.
// Returns the monitor URL.
func startMonitoredExecave(t *testing.T, configPath string, command ...string) string {
	t.Helper()

	args := append([]string{"--config", configPath, "--monitor", "--no-open", "--"}, command...)
	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	cmd.Stdout = os.Stdout

	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		_ = cmd.Wait()
	})

	var monitorURL string
	var once sync.Once
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			if after, ok := strings.CutPrefix(scanner.Text(), "execave: monitor running at "); ok {
				monitorURL = after
				once.Do(func() { close(ready) })
			}
		}
		once.Do(func() { close(ready) })
	}()
	<-ready
	require.NotEmpty(t, monitorURL)

	return monitorURL
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
