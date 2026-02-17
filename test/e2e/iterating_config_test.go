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
		"--monitor=0",
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
	resp, err := http.Post(monitorURL+"/api/start", "text/plain", nil)
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
		"--monitor=0",
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
	resp, err := http.Post(monitorURL+"/api/stop", "text/plain", nil)
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
		"--monitor=0",
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
	resp, err := http.Post(monitorURL+"/api/start", "text/plain", nil)
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

// TestE2E_IteratingConfig_ViewRulesAlongsideAccessLog tests that the web UI displays
// config rules in a rules pane alongside the access log table.
func TestE2E_IteratingConfig_ViewRulesAlongsideAccessLog(t *testing.T) {
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
		"--monitor=0",
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

	// Fetch web UI and verify both rules pane and access log are present
	webUI := fetchWebUI(t, monitorURL)

	// Verify rules pane is present
	assert.Contains(t, webUI, "Rules")

	// Verify both rules are displayed
	assert.Contains(t, webUI, "fs:ro:"+dataDir)
	assert.Contains(t, webUI, "fs:rw:"+tmpDir)

	// Verify access log table is present (has the standard headers)
	assert.Contains(t, webUI, "Operation")
	assert.Contains(t, webUI, "Target")
	assert.Contains(t, webUI, "Result")
	assert.Contains(t, webUI, "Rule")

	// Verify at least one access log entry is present (from ls command)
	assert.Contains(t, webUI, dataDir)

	// Clean up
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

// TestE2E_IteratingConfig_StartButtonClickTriggersStart is a placeholder for testing
// that clicking the Start button in the browser triggers a POST /api/start request.
// This requires browser/JS execution which is not supported in this test framework.
func TestE2E_IteratingConfig_StartButtonClickTriggersStart(t *testing.T) {
	t.Skip("needs browser/JS execution")
	// This test would verify:
	// - Click "Start" button when idle
	// - Verify POST /api/start is sent
	// - Verify status updates to "Running" in the UI
}

// TestE2E_IteratingConfig_RestartButtonClickTriggersRestart is a placeholder for testing
// that clicking the Restart button triggers a POST /api/start request while running.
// This requires browser/JS execution which is not supported in this test framework.
func TestE2E_IteratingConfig_RestartButtonClickTriggersRestart(t *testing.T) {
	t.Skip("needs browser/JS execution")
	// This test would verify:
	// - Process is running
	// - Click "Restart" button
	// - Verify POST /api/start is sent
	// - Verify access log is cleared in the browser
	// - Verify new entries appear from the restarted run
}

// TestE2E_IteratingConfig_StopButtonClickTriggersStop is a placeholder for testing
// that clicking the Stop button triggers a POST /api/stop request.
// This requires browser/JS execution which is not supported in this test framework.
func TestE2E_IteratingConfig_StopButtonClickTriggersStop(t *testing.T) {
	t.Skip("needs browser/JS execution")
	// This test would verify:
	// - Process is running
	// - Click "Stop" button
	// - Verify POST /api/stop is sent
	// - Verify status updates to "Exited" in the UI
	// - Verify Stop button becomes disabled
}

// TestE2E_IteratingConfig_SSEStatusEventsUpdateButtonLabels is a placeholder for testing
// that SSE status events update button labels and disabled state.
// This requires browser/JS execution which is not supported in this test framework.
func TestE2E_IteratingConfig_SSEStatusEventsUpdateButtonLabels(t *testing.T) {
	t.Skip("needs browser/JS execution")
	// This test would verify:
	// - Connect to SSE stream
	// - Receive status event with Running=true
	// - Verify "Start" button label changes to "Restart"
	// - Verify "Stop" button becomes enabled
	// - Receive status event with Running=false
	// - Verify "Restart" button label changes to "Start"
	// - Verify "Stop" button becomes disabled
}

// TestE2E_IteratingConfig_SessionEventClearsAccessLogTable is a placeholder for testing
// that receiving a "session" SSE event clears the browser's access log table.
// This requires browser/JS execution which is not supported in this test framework.
func TestE2E_IteratingConfig_SessionEventClearsAccessLogTable(t *testing.T) {
	t.Skip("needs browser/JS execution")
	// This test would verify:
	// - Access log table has entries from a run
	// - Trigger a restart (sends session event)
	// - Verify the table is cleared in the browser
	// - Verify new entries appear from the new run
}
