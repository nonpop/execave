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

// monitoredResult contains the result of a monitored execave run,
// including the web UI HTML content for entry assertions.
type monitoredResult struct {
	execaveResult

	WebUI      string
	MonitorURL string
	ConfigDir  string // directory of the config file used for this run
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
	lastWebUI  string
	monitorURL string
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
		lastWebUI:  "",
		monitorURL: "",
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
	s.lastWebUI = ""
	s.monitorURL = ""
}

// whenRunWithDefaultConfig executes execave without --config, relying on default config location.
func (s *scenario) whenRunWithDefaultConfig(workDir string, args ...string) {
	s.t.Helper()
	execArgs := append([]string{"--"}, args...)
	result := runExecave(s.t, workDir, execArgs...)
	s.lastResult = &result
	s.lastWebUI = ""
	s.monitorURL = ""
}

// whenRunMonitored executes execave with monitoring enabled.
// Lazily checks for strace availability.
func (s *scenario) whenRunMonitored(args ...string) {
	s.t.Helper()
	failIfNoStrace(s.t)
	execArgs := make([]string, 0, 6+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--monitor", "--no-open", "--")
	execArgs = append(execArgs, args...)
	result := runExecaveMonitored(s.t, execArgs...)
	s.lastResult = &result.execaveResult
	s.lastWebUI = result.WebUI
	s.monitorURL = result.MonitorURL
}

// whenRunMonitoredWithInterrupt runs monitored execave and sends SIGINT during execution.
func (s *scenario) whenRunMonitoredWithInterrupt(args ...string) {
	s.t.Helper()
	failIfNoStrace(s.t)
	execArgs := make([]string, 0, 6+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--monitor", "--no-open", "--")
	execArgs = append(execArgs, args...)
	result := runMonitoredCmd(s.t, monitorRunOpts{
		readyLine:     "execave: monitor running at ",
		preFetchDelay: 200 * time.Millisecond,
	}, execArgs...)
	s.lastResult = &result.execaveResult
	s.lastWebUI = result.WebUI
	s.monitorURL = result.MonitorURL
}

// whenRunMonitoredWithFlags executes monitored execave with extra flags.
func (s *scenario) whenRunMonitoredWithFlags(flags []string, args ...string) {
	s.t.Helper()
	failIfNoStrace(s.t)
	execArgs := make([]string, 0, 6+len(flags)+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--monitor", "--no-open")
	execArgs = append(execArgs, flags...)
	execArgs = append(execArgs, "--")
	execArgs = append(execArgs, args...)
	result := runExecaveMonitored(s.t, execArgs...)
	s.lastResult = &result.execaveResult
	s.lastWebUI = result.WebUI
	s.monitorURL = result.MonitorURL
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
	s.lastWebUI = ""
	s.monitorURL = ""
}

// whenRunTextLogWithFlags executes execave with --monitor=<monitorArg> and extra flags.
func (s *scenario) whenRunTextLogWithFlags(monitorArg string, flags []string, args ...string) {
	s.t.Helper()
	failIfNoStrace(s.t)
	execArgs := make([]string, 0, 5+len(flags)+len(args))
	execArgs = append(execArgs, "--config", s.configPath, "--monitor="+monitorArg)
	execArgs = append(execArgs, flags...)
	execArgs = append(execArgs, "--")
	execArgs = append(execArgs, args...)
	result := runExecave(s.t, "", execArgs...)
	s.lastResult = &result
	s.lastWebUI = ""
	s.monitorURL = ""
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

// thenFileContains asserts that the file at path exists and contains sub.
func (s *scenario) thenFileContains(path, sub string) {
	s.t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test code reading controlled test files
	require.NoError(s.t, err)
	assert.Contains(s.t, string(data), sub)
}

// thenWebUIHasEntry asserts that the web UI HTML contains a table row with all substrings.
func (s *scenario) thenWebUIHasEntry(substrings ...string) {
	s.t.Helper()
	require.NotEmpty(s.t, s.lastWebUI)
	assertWebUIHasEntry(s.t, s.lastWebUI, substrings...)
}

// thenWebUIContains asserts the raw web UI HTML contains sub.
func (s *scenario) thenWebUIContains(sub string) {
	s.t.Helper()
	require.NotEmpty(s.t, s.lastWebUI)
	assert.Contains(s.t, s.lastWebUI, sub)
}

// thenWebUINotContains asserts the raw web UI HTML does not contain sub.
func (s *scenario) thenWebUINotContains(sub string) {
	s.t.Helper()
	require.NotEmpty(s.t, s.lastWebUI)
	assert.NotContains(s.t, s.lastWebUI, sub)
}

// thenWebUICountOf counts occurrences of sub in the web UI HTML.
func (s *scenario) thenWebUICountOf(sub string) int {
	s.t.Helper()
	require.NotEmpty(s.t, s.lastWebUI)
	return strings.Count(s.lastWebUI, sub)
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
