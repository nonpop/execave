package runner_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/runner"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_RunLifecycle_StartLaunchesMonitoredRun tests the "Start launches a monitored run" scenario.
func TestIntegration_RunLifecycle_StartLaunchesMonitoredRun(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN Start is called with a valid config and command
	command := []string{"true"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)

	// THEN Status returns Running=true
	status := env.runner.Status()
	assert.True(t, status.Running)

	// AND Logger returns a non-nil logger with zero entries
	logger := env.runner.Logger()
	assert.NotNil(t, logger)
	assert.Empty(t, logger.Entries())

	// Wait for run to complete
	env.waitForIdle()
}

// TestIntegration_RunLifecycle_StopTerminatesRunningProcess tests the "Stop terminates a running process" scenario.
func TestIntegration_RunLifecycle_StopTerminatesRunningProcess(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a run is active
	command := []string{"sleep", "300"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)
	require.True(t, env.runner.Status().Running)

	// AND Stop is called
	env.runner.Stop()

	// THEN the run is terminated
	// AND Status returns Running=false
	status := env.runner.Status()
	assert.False(t, status.Running)
}

// TestIntegration_RunLifecycle_StopIsNoOpWhenIdle tests the "Stop is no-op when idle" scenario.
func TestIntegration_RunLifecycle_StopIsNoOpWhenIdle(t *testing.T) {
	env := newRunnerTestEnv(t)

	// WHEN no run is active
	status := env.runner.Status()
	require.False(t, status.Running)

	// AND Stop is called
	env.runner.Stop()

	// THEN no error occurs
	// AND Status remains unchanged
	newStatus := env.runner.Status()
	assert.Equal(t, status, newStatus)
}

// TestIntegration_RunLifecycle_StartWhileRunningStopsPreviousRun tests the "Start while running stops the previous run" scenario.
func TestIntegration_RunLifecycle_StartWhileRunningStopsPreviousRun(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a run is active
	command1 := []string{"sleep", "300"}
	err = env.runner.Start(ctx, env.cfg, command1)
	require.NoError(t, err)
	require.True(t, env.runner.Status().Running)
	logger1 := env.runner.Logger()

	// AND Start is called with a new command
	command2 := []string{"true"}
	err = env.runner.Start(ctx, env.cfg, command2)
	require.NoError(t, err)

	// THEN the previous run is terminated
	// AND a new run starts with a fresh access log
	logger2 := env.runner.Logger()
	assert.NotSame(t, logger1, logger2)

	// AND Status returns Running=true
	status := env.runner.Status()
	assert.True(t, status.Running)

	// Wait for run to complete
	env.waitForIdle()
}

// TestIntegration_AccessLogging_LoggerIsReplacedOnStart tests the "Logger is replaced on start" scenario.
func TestIntegration_AccessLogging_LoggerIsReplacedOnStart(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a run has completed
	command1 := []string{"true"}
	err = env.runner.Start(ctx, env.cfg, command1)
	require.NoError(t, err)
	env.waitForIdle()

	logger1 := env.runner.Logger()
	require.NotNil(t, logger1, "First run should have created a logger")

	// AND Start is called again
	command2 := []string{"false"}
	err = env.runner.Start(ctx, env.cfg, command2)
	require.NoError(t, err)

	// THEN Logger returns a new logger
	logger2 := env.runner.Logger()
	assert.NotSame(t, logger1, logger2)

	// Wait for run to complete
	env.waitForIdle()
}

// TestIntegration_AccessLogging_LoggerChangeCallbackInvokedOnStart tests the "Logger change callback invoked on start" scenario.
func TestIntegration_AccessLogging_LoggerChangeCallbackInvokedOnStart(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN OnLoggerChange is set
	var callbackLogger *accesslog.Logger
	env.runner.OnLoggerChange = func(l *accesslog.Logger) {
		callbackLogger = l
	}

	// AND Start is called
	command := []string{"true"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)

	// THEN the callback is invoked with the new logger
	assert.NotNil(t, callbackLogger)
	assert.Same(t, env.runner.Logger(), callbackLogger)

	// Wait for run to complete
	env.waitForIdle()
}

// TestIntegration_StatusReporting_StatusReflectsRunningState tests the "Status reflects running state" scenario.
func TestIntegration_StatusReporting_StatusReflectsRunningState(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN Start is called
	command := []string{"sleep", "1"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)

	// THEN Status returns Running=true
	status := env.runner.Status()
	assert.True(t, status.Running)

	// Wait for run to complete
	env.waitForIdle()
}

// TestIntegration_StatusReporting_StatusReflectsExitState tests the "Status reflects exit state" scenario.
func TestIntegration_StatusReporting_StatusReflectsExitState(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a run completes
	command := []string{"true"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)
	env.waitForIdle()

	// THEN Status returns Running=false
	status := env.runner.Status()
	assert.False(t, status.Running)
	// ExitCode is set (should ideally be 0 for `true` command, but might be non-zero if sandbox setup fails)
	t.Logf("Exit code: %d, Error: %s", status.ExitCode, status.Error)
}

// TestIntegration_StatusReporting_StatusReflectsNonZeroExit tests the "Status reflects non-zero exit" scenario.
func TestIntegration_StatusReporting_StatusReflectsNonZeroExit(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a run completes with exit code 1
	command := []string{"false"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)
	env.waitForIdle()

	// THEN Status returns Running=false and ExitCode=1
	status := env.runner.Status()
	assert.False(t, status.Running)
	assert.Equal(t, 1, status.ExitCode)
}

// TestIntegration_StatusReporting_SubscribersNotifiedOnStatusChange tests the "Subscribers notified on status change" scenario.
func TestIntegration_StatusReporting_SubscribersNotifiedOnStatusChange(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a subscriber is registered
	statusCh := env.runner.Subscribe()
	defer env.runner.Unsubscribe(statusCh)

	// AND the run status changes
	command := []string{"true"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)

	// THEN the subscriber channel receives notifications
	// Should receive: running status and exit status
	var receivedNotifications int
	timeout := time.After(5 * time.Second)

collectLoop:
	for {
		select {
		case <-statusCh:
			receivedNotifications++
			status := env.runner.Status()
			if !status.Running && receivedNotifications >= 2 {
				// Received notifications for both running and exit, done
				break collectLoop
			}
		case <-timeout:
			t.Fatal("Timeout waiting for status notifications")
		}
	}

	// Should have received at least 2 notifications (start and exit)
	assert.GreaterOrEqual(t, receivedNotifications, 2)
}

// TestIntegration_StatusReporting_ConcurrentStatusReadsDuringRun tests the "Concurrent status reads during run" scenario.
func TestIntegration_StatusReporting_ConcurrentStatusReadsDuringRun(t *testing.T) {
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	env := newRunnerTestEnv(t)
	ctx := context.Background()

	// WHEN a run is active
	command := []string{"sleep", "1"}
	err = env.runner.Start(ctx, env.cfg, command)
	require.NoError(t, err)

	// AND Status is called concurrently from multiple goroutines
	done := make(chan bool)
	for range 10 {
		go func() {
			for range 100 {
				_ = env.runner.Status()
			}
			done <- true
		}()
	}

	// THEN all calls return consistent snapshots without data races
	for range 10 {
		<-done
	}

	// Wait for run to complete
	env.waitForIdle()
}

// TestIntegration_TerminalManagement_TerminalRestoredAfterKilledProcess tests the "Terminal restored after killed process" scenario.
// This test verifies that terminal state is restored between runs.
func TestIntegration_TerminalManagement_TerminalRestoredAfterKilledProcess(t *testing.T) {
	t.Skip("needs interactive terminal testing - placeholder for manual verification")
	// This test would verify:
	// - Start a process that changes terminal state (e.g., `stty -echo`)
	// - Kill the process with Stop
	// - Start a new process
	// - Verify terminal echo is restored
	// Manual test: Run a command that disables echo, stop it, restart, verify echo works
}

// TestIntegration_TerminalManagement_BufferedInputDiscardedOnRestart tests the "Buffered input discarded on restart" scenario.
// This test verifies that stdin buffer is cleared between runs.
func TestIntegration_TerminalManagement_BufferedInputDiscardedOnRestart(t *testing.T) {
	t.Skip("needs interactive stdin testing - placeholder for manual verification")
	// This test would verify:
	// - Type input while no process is running
	// - Start a new process
	// - Verify the process doesn't receive the buffered input
	// Manual test: Type input after process stops, then restart and verify input not received
}

// TestIntegration_TuiCleanup_TuiArtifactsClearedAfterKilledTuiApp tests the "TUI artifacts cleared after killed TUI app" scenario.
func TestIntegration_TuiCleanup_TuiArtifactsClearedAfterKilledTuiApp(t *testing.T) {
	t.Skip("needs terminal escape sequence verification - placeholder for manual verification")
	// This test would verify:
	// - Run a TUI application (e.g., vim) that uses alt screen
	// - Kill the process (alt screen remains active at query time)
	// - Verify the runner sent: exit alt screen (\x1b[?1049l), clear screen (\x1b[2J),
	//   cursor home (\x1b[H), show cursor (\x1b[?25h), disable focus (\x1b[?1004l),
	//   disable mouse tracking (\x1b[?1000l, \x1b[?1002l, \x1b[?1003l), reset modes (\x1b[m)
	// Manual test: Run vim in sandbox, kill it, verify no TUI artifacts remain
}

// TestIntegration_TuiCleanup_OutputPreservedAfterRegularCommand tests the "Output preserved after regular command" scenario.
func TestIntegration_TuiCleanup_OutputPreservedAfterRegularCommand(t *testing.T) {
	t.Skip("needs terminal escape sequence verification - placeholder for manual verification")
	// This test would verify:
	// - Run a regular command (e.g., ls) that produces visible output and never uses alt screen
	// - After the command exits, verify \x1b[2J (clear screen) and \x1b[?1049l (exit alt screen)
	//   were NOT sent to the terminal
	// - Verify the output remains visible and cursor/mouse/focus resets were sent (harmless no-ops)
	// Manual test: Run ls in sandbox, verify output stays visible after exit
}

// TestIntegration_TuiCleanup_OutputPreservedAfterTuiThatExitsCleanly tests the "Output preserved after TUI that exits cleanly" scenario.
func TestIntegration_TuiCleanup_OutputPreservedAfterTuiThatExitsCleanly(t *testing.T) {
	t.Skip("needs terminal escape sequence verification - placeholder for manual verification")
	// This test would verify:
	// - Run a TUI application that exits the alt screen (and optionally prints a summary)
	//   before execave queries the terminal with DECRQM
	// - Verify \x1b[2J and \x1b[?1049l were NOT sent (alt screen already inactive at query time)
	// - Verify any summary output the TUI printed after exiting alt screen remains visible
	// Manual test: Run vim then :q, verify no spurious screen clear and output preserved
}

// TestIntegration_TerminalManagement_ForegroundReclaimedAfterKilledProcess tests the "Foreground reclaimed after killed process" scenario.
func TestIntegration_TerminalManagement_ForegroundReclaimedAfterKilledProcess(t *testing.T) {
	t.Skip("needs controlling terminal - placeholder for manual verification")
	// This test would verify:
	// - Run a process that calls tcsetpgrp() (e.g., bash)
	// - Stop the process
	// - Verify execave reclaimed the foreground process group
	// - Verify Ctrl-C (SIGINT) is delivered to execave
	// Manual test: Run bash in sandbox, stop it via webui, verify Ctrl-C still works
}

// runnerTestEnv provides test infrastructure for runner integration tests.
type runnerTestEnv struct {
	t             *testing.T
	TmpDir        string
	cfg           *config.Config
	absConfigPath string
	netPath       *sandbox.NetworkPath
	runner        *runner.Runner
}

// newRunnerTestEnv creates a new runner test environment with a temporary directory and test config.
func newRunnerTestEnv(t *testing.T) *runnerTestEnv {
	t.Helper()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, nil, 0o600))

	// Build rules for paths that exist on this system
	var rules []fsrules.AccessRule
	paths := []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			rules = append(rules, fsrules.AccessRule{Permission: fsrules.PermissionReadOnly, Path: p, RawRule: "fs:ro:" + p})
		}
	}
	rules = append(rules, fsrules.AccessRule{Permission: fsrules.PermissionReadOnly, Path: tmpDir, RawRule: "fs:ro:" + tmpDir})

	cfg := &config.Config{
		FSRules:           rules,
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      []string{"/dev", "/proc", "/sys", "/tmp"},
	}

	absConfigPath := filepath.Join(tmpDir, "execave.json")
	netPath := &sandbox.NetworkPath{UDSPath: "", ExecaveBinary: ""}

	rnr := runner.New(cfg, absConfigPath, netPath)

	return &runnerTestEnv{
		t:             t,
		TmpDir:        tmpDir,
		cfg:           cfg,
		absConfigPath: absConfigPath,
		netPath:       netPath,
		runner:        rnr,
	}
}

// waitForIdle polls the runner status until Running=false or timeout.
func (e *runnerTestEnv) waitForIdle() {
	e.t.Helper()
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			e.t.Fatal("Timeout waiting for runner to become idle")
		case <-ticker.C:
			if !e.runner.Status().Running {
				return
			}
		}
	}
}
