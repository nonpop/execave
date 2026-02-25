package e2e_test

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_IteratingConfig_StartRunFromWebUI tests that the user can start a new
// monitored run from the web UI after the initial run has exited.
func TestE2E_IteratingConfig_StartRunFromWebUI(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	data.file("file.txt", "test data")

	rules := append(systemPaths(), "fs:ro:"+data.String())
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"ls", data.String())
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
	assert.Contains(t, webUI, "Exited")

	resp, err := http.Post(monitorEndpoint(monitorURL, "/api/start"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(500 * time.Millisecond)

	webUI2 := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI2, data.String())

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_StopRunningProcessFromWebUI tests that the user can stop
// a long-running sandboxed process from the web UI without killing the monitor.
func TestE2E_IteratingConfig_StopRunningProcessFromWebUI(t *testing.T) {
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	data.file(".keep", "")

	rules := append(systemPaths(), "fs:ro:"+data.String())
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"sh", "-c", "sleep 30")
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
	assert.Contains(t, webUI, "Running")

	resp, err := http.Post(monitorEndpoint(monitorURL, "/api/stop"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(500 * time.Millisecond)

	webUI2 := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI2, "Exited")

	resp2, err := http.Get(monitorURL) //nolint:gosec // G107: test uses controlled URL from test fixture
	require.NoError(t, err)
	defer resp2.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_RestartReplacesActiveRun tests that clicking "Restart"
// while a process is running stops the active run and starts a new one with a fresh
// access log.
func TestE2E_IteratingConfig_RestartReplacesActiveRun(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	file1 := data.file("file1.txt", "data 1")
	data.file("file2.txt", "data 2")

	rules := append(systemPaths(), "fs:ro:"+data.String())
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"sh", "-c", "cat "+file1+" && sleep 30")
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
	assert.Contains(t, webUI, "Running")
	assert.Contains(t, webUI, file1)

	resp, err := http.Post(monitorEndpoint(monitorURL, "/api/start"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(500 * time.Millisecond)

	webUI2 := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI2, file1)

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_ViewConfigAlongsideAccessLog tests that the web UI displays
// a config textarea alongside the access log table.
func TestE2E_IteratingConfig_ViewConfigAlongsideAccessLog(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	tmp := s.givenDir("tmp")
	data.file("file.txt", "test data")
	tmp.file("out.txt", "output")

	rules := append(systemPaths(), "fs:ro:"+data.String(), "fs:rw:"+tmp.String())
	configPath := writeConfig(t, rules)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"ls", data.String())
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

	assert.Contains(t, webUI, "Config")
	assert.Contains(t, webUI, "fs:ro:"+data.String())
	assert.Contains(t, webUI, "fs:rw:"+tmp.String())
	assert.Contains(t, webUI, "Operation")
	assert.Contains(t, webUI, "Target")
	assert.Contains(t, webUI, "Result")
	assert.Contains(t, webUI, data.String())

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_ConfigEventReflectsCurrentConfig tests that a connecting SSE
// client receives a config event containing the current config content.
func TestE2E_IteratingConfig_ConfigEventReflectsCurrentConfig(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	data.file("file.txt", "test data")

	newNetRule := "net:http:127.0.0.1:9999"
	rules := append(systemPaths(), "fs:ro:"+data.String(), newNetRule)
	configPath := writeConfig(t, rules)

	monitorURL := startMonitoredExecave(t, configPath, "sleep", "60")

	req, err := http.NewRequest(http.MethodGet, monitorEndpoint(monitorURL, "/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "old-session:0")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	events := readSSEEvents(resp, 3)
	require.GreaterOrEqual(t, len(events), 3)

	var configData string
	for _, ev := range events {
		if ev.event == "config" {
			configData = ev.data
			break
		}
	}
	require.NotEmpty(t, configData)

	assert.Contains(t, configData, "fs:ro:"+data.String())
	assert.Contains(t, configData, newNetRule)
}

// TestE2E_IteratingConfig_HoverARuleToSeeMatchingLogEntries is a placeholder.
func TestE2E_IteratingConfig_HoverARuleToSeeMatchingLogEntries(t *testing.T) {
	t.Skip("hover interaction requires JavaScript execution in a browser; see comment above")
}

// TestE2E_IteratingConfig_HoverALogEntryToSeeItsMatchedRule is a placeholder.
func TestE2E_IteratingConfig_HoverALogEntryToSeeItsMatchedRule(t *testing.T) {
	t.Skip("hover interaction requires JavaScript execution in a browser; see comment above")
}
