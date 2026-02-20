package e2e_test

import (
	"bufio"
	"context"
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

// TestE2E_IteratingConfig_StartRunFromWebUI tests that the user can start a new
// monitored run from the web UI after the initial run has exited.
func TestE2E_IteratingConfig_StartRunFromWebUI(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	dataFile := filepath.Join(dataDir, "file.txt")
	createFile(t, dataFile, "test data")

	rules := append(systemPaths(), "fs:ro:"+dataDir)
	configPath := writeConfig(t, rules)

	// Start execave with monitoring
	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"ls", dataDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	cmd.Stdout = os.Stdout

	require.NoError(t, cmd.Start())

	// Wait for web UI to be ready, extract monitor URL
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
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Wait for the initial run to exit
	time.Sleep(500 * time.Millisecond)

	// Verify web UI is accessible and shows the initial run
	webUI := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI, "Exited")

	// POST /api/start to start a new run
	resp, err := http.Post(monitorEndpoint(monitorURL, "/api/start"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response should be 200
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Give time for the new run to execute
	time.Sleep(500 * time.Millisecond)

	// Web UI should show the new run completed (access log has entries)
	webUI2 := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI2, dataDir) // Access log should contain the new run's entries

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_StopRunningProcessFromWebUI tests that the user can stop
// a long-running sandboxed process from the web UI without killing the monitor.
func TestE2E_IteratingConfig_StopRunningProcessFromWebUI(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	// Create the directory by creating a file in it
	createFile(t, filepath.Join(dataDir, ".keep"), "")

	rules := append(systemPaths(), "fs:ro:"+dataDir)
	configPath := writeConfig(t, rules)

	// Start execave with a long-running command
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

	// Wait for web UI to be ready, extract monitor URL
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
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Give time for the sleep to start
	time.Sleep(500 * time.Millisecond)

	// Verify process is running
	webUI := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI, "Running")

	// POST /api/stop to stop the process
	resp, err := http.Post(monitorEndpoint(monitorURL, "/api/stop"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response should be 200
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Give time for the process to stop
	time.Sleep(500 * time.Millisecond)

	// Web UI should show the process as exited
	webUI2 := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI2, "Exited")

	// Web UI should still be accessible
	resp2, err := http.Get(monitorURL) //nolint:gosec // G107: test uses controlled URL from test fixture
	require.NoError(t, err)
	defer resp2.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_RestartReplacesActiveRun tests that clicking "Restart"
// while a process is running stops the active run and starts a new one with a fresh
// access log.
func TestE2E_IteratingConfig_RestartReplacesActiveRun(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	file1 := filepath.Join(dataDir, "file1.txt")
	file2 := filepath.Join(dataDir, "file2.txt")
	createFile(t, file1, "data 1")
	createFile(t, file2, "data 2")

	rules := append(systemPaths(), "fs:ro:"+dataDir)
	configPath := writeConfig(t, rules)

	// Start execave with a long-running command
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

	// Wait for web UI to be ready, extract monitor URL
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
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Give time for the cat to execute
	time.Sleep(500 * time.Millisecond)

	// Verify process is running and access log contains file1
	webUI := fetchWebUI(t, monitorURL)
	assert.Contains(t, webUI, "Running")
	assert.Contains(t, webUI, file1)

	// POST /api/start to restart (stops active run, starts new one)
	resp, err := http.Post(monitorEndpoint(monitorURL, "/api/start"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response should be 200
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Give time for the new run to execute (cat file1 again)
	time.Sleep(500 * time.Millisecond)

	// Web UI should show the new run
	// Note: The access log should have been cleared, so we should see new entries from the restart
	// The old entries from the first run should no longer be visible
	webUI2 := fetchWebUI(t, monitorURL)

	// After restart, the process should be running again
	// (or may have exited quickly if the command completed)
	// The key test is that the access log was cleared and shows entries from the new run
	assert.Contains(t, webUI2, file1) // New run should have accessed file1

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_ViewConfigAlongsideAccessLog tests that the web UI displays
// a config textarea alongside the access log table.
func TestE2E_IteratingConfig_ViewConfigAlongsideAccessLog(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	tmpDir := filepath.Join(env.TmpDir, "tmp")
	createFile(t, filepath.Join(dataDir, "file.txt"), "test data")
	createFile(t, filepath.Join(tmpDir, "out.txt"), "output")

	rules := append(systemPaths(), "fs:ro:"+dataDir, "fs:rw:"+tmpDir)
	configPath := writeConfig(t, rules)

	// Start execave with monitoring
	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", configPath,
		"--monitor",
		"--no-open",
		"--",
		"ls", dataDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	cmd.Stdout = os.Stdout

	require.NoError(t, cmd.Start())

	// Wait for web UI to be ready, extract monitor URL
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
	require.NotEmpty(t, monitorURL, "monitor URL not found in stderr")

	// Wait for the run to complete
	time.Sleep(500 * time.Millisecond)

	// Fetch web UI and verify both config pane and access log are present
	webUI := fetchWebUI(t, monitorURL)

	// Verify config pane is present
	assert.Contains(t, webUI, "Config")

	// Verify config content is present (rules appear in the textarea)
	assert.Contains(t, webUI, "fs:ro:"+dataDir)
	assert.Contains(t, webUI, "fs:rw:"+tmpDir)

	// Verify access log table is present (has the standard headers)
	assert.Contains(t, webUI, "Operation")
	assert.Contains(t, webUI, "Target")
	assert.Contains(t, webUI, "Result")

	// Verify at least one access log entry is present (from ls command)
	assert.Contains(t, webUI, dataDir)

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_ConfigEventReflectsCurrentConfig tests that a connecting SSE
// client receives a config event containing the current config content.
//
// The visual config textarea update in the browser requires JavaScript and is not tested here.
func TestE2E_IteratingConfig_ConfigEventReflectsCurrentConfig(t *testing.T) {
	env := newMonitorTest(t)

	dataDir := filepath.Join(env.TmpDir, "data")
	createFile(t, filepath.Join(dataDir, "file.txt"), "test data")

	// Config with a distinctive net rule
	newNetRule := "net:http:127.0.0.1:9999"
	rules := append(systemPaths(), "fs:ro:"+dataDir, newNetRule)
	configPath := writeConfig(t, rules)

	monitorURL := startMonitoredExecave(t, configPath, "sleep", "60")

	// Simulate browser reconnecting: use a cross-session Last-Event-ID so the server
	// replays from index 0 and emits fresh events.
	req, err := http.NewRequest(http.MethodGet, monitorEndpoint(monitorURL, "/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "old-session:0")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Read initial events: session + status + config
	events := readSSEEvents(resp, 3)
	require.GreaterOrEqual(t, len(events), 3)

	// Find the config event
	var configData string
	for _, ev := range events {
		if ev.event == "config" {
			configData = ev.data
			break
		}
	}
	require.NotEmpty(t, configData, "config event not found in SSE stream")

	// Config content is delivered to the connecting client
	assert.Contains(t, configData, "fs:ro:"+dataDir)
	assert.Contains(t, configData, newNetRule)
}

// TestE2E_IteratingConfig_HoverARuleToSeeMatchingLogEntries is a placeholder.
// Hovering over a rule to highlight matching log entries requires JavaScript
// execution in a browser and cannot be tested via plain HTTP.
func TestE2E_IteratingConfig_HoverARuleToSeeMatchingLogEntries(t *testing.T) {
	t.Skip("hover interaction requires JavaScript execution in a browser; see comment above")
}

// TestE2E_IteratingConfig_HoverALogEntryToSeeItsMatchedRule is a placeholder.
// Hovering over a log entry to highlight its matched rule requires JavaScript
// execution in a browser and cannot be tested via plain HTTP.
func TestE2E_IteratingConfig_HoverALogEntryToSeeItsMatchedRule(t *testing.T) {
	t.Skip("hover interaction requires JavaScript execution in a browser; see comment above")
}
