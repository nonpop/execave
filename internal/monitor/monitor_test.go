package monitor_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/binutil"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/exitcode"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/syscallrules"
	"github.com/nonpop/execave/internal/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runMonitorDirect runs a command via strace with the given processor configuration.
// This is a test helper for tests that need to directly configure monitor parameters.
func runMonitorDirect(
	tb testing.TB,
	stracePath string,
	logger *accesslog.Logger,
	fsResolver *fsrules.Resolver,
	cmd []string,
	setupExecves int,
	extraFile *os.File,
	syscallResolver *syscallrules.Resolver,
	unenforced bool,
) (int, error) {
	tb.Helper()

	processor := monitor.New(logger, fsResolver, syscallResolver, setupExecves, unenforced)
	prepared, err := monitor.Prepare(stracePath, cmd, extraFile, syscallResolver, 3)
	if err != nil {
		return 1, fmt.Errorf("prepare monitor: %w", err)
	}

	execCmd := exec.CommandContext(context.Background(), prepared.StracePath, prepared.Args...) // #nosec G204
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.ExtraFiles = prepared.ExtraFiles

	if startErr := execCmd.Start(); startErr != nil {
		prepared.Abort()
		return 1, fmt.Errorf("start strace: %w", startErr)
	}
	prepared.Started()

	processingErrCh := make(chan error, 1)
	go func() {
		processingErrCh <- processor.Run(prepared.StraceReader)
		_ = prepared.StraceReader.Close()
	}()

	waitErr := execCmd.Wait()
	_ = prepared.StraceReader.Close()

	code, exitErr := exitcode.Extract(waitErr)
	if exitErr != nil {
		return code, fmt.Errorf("execute strace: %w", exitErr)
	}

	processingErr := <-processingErrCh
	if processingErr != nil {
		if !errors.Is(processingErr, os.ErrClosed) {
			return code, fmt.Errorf("process strace output: %w", processingErr)
		}
	}

	return code, nil
}

func roRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
		SourcePath: "",
	}
}

// formatEntries returns the log buffer contents for assertions.
func formatEntries(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	logStr := buf.String()
	t.Logf("Log content:\n%s", logStr)
	return logStr
}

// assertLogContainsLine checks that the log contains at least one line
// that includes all of the given components (in any order).
func assertLogContainsLine(t *testing.T, logStr string, components ...string) {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(logStr), "\n") {
		allFound := true
		for _, component := range components {
			if !strings.Contains(line, component) {
				allFound = false
				break
			}
		}
		if allFound {
			return
		}
	}
	t.Errorf("no line found containing all components: %v", components)
}

// countLogLines returns the number of log entries in s (one per newline).
func countLogLines(s string) int {
	return strings.Count(s, "\n")
}

// createTestProcessor creates a Monitor with a logger for testing.
// Returns the monitor and the log buffer.
// setupExecves controls how many execves to skip in strace output.
func createTestProcessor(t *testing.T, cfg *config.Config, setupExecves int) (*monitor.Monitor, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, HomeDir: "", ConfigDir: "", ShowAllowed: true}
	logger := accesslog.New(&buf, logCfg)
	fsResolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	return monitor.New(logger, fsResolver, nil, setupExecves, false), &buf
}

// createCwdTestProcessor creates a temp dir with a file.txt and a monitor with a ro rule for it.
// Returns the temp dir, monitor, and log buffer.
func createCwdTestProcessor(t *testing.T) (string, *monitor.Monitor, *bytes.Buffer) {
	t.Helper()
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("data"), 0o600))
	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(tmpDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	proc, buf := createTestProcessor(t, cfg, 0)
	return tmpDir, proc, buf
}

// assertBlockedSyscallEntry verifies that processing a strace line for a blocked syscall
// produces a single SYSCALL DENY entry with the expected target name.
func assertBlockedSyscallEntry(t *testing.T, syscallName, straceLine string) {
	t.Helper()
	syscallResolver := syscallrules.NewResolver(nil, seccomp.RuleableSyscallNames())
	cfg := new(config.Config)
	var buf bytes.Buffer
	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, HomeDir: "", ConfigDir: "", ShowAllowed: true}
	logger := accesslog.New(&buf, logCfg)
	fsResolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	mon := monitor.New(logger, fsResolver, syscallResolver, 0, false)

	err := mon.Run(strings.NewReader(straceLine + "\n"))
	require.NoError(t, err)

	logStr := buf.String()
	require.Equal(t, 1, countLogLines(logStr))
	assert.Contains(t, logStr, "SYSCALL")
	assert.Contains(t, logStr, syscallName)
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, "("+accesslog.RuleNoMatch+")")
}

func Test_BwrapSetupPhaseDetection_IncompleteExecveChainStillProducesEntries(t *testing.T) {
	_, err := binutil.ResolveBwrap()
	require.NoError(t, err)
	stracePath, err := binutil.ResolveStrace()
	require.NoError(t, err)

	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	testFile := filepath.Join(absTestDir, "file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("hello"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			roRule("/usr"), roRule("/lib"), roRule("/lib64"), roRule("/etc/ld.so.cache"),
			roRule(absTestDir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	var logBuf bytes.Buffer
	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, HomeDir: "", ConfigDir: "", ShowAllowed: true}
	logger := accesslog.New(&logBuf, logCfg)
	resolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)

	// Create a stub tunnel script that skips "network-tunnel <uds> --" and execs the rest.
	tunnelStub := filepath.Join(absTestDir, "tunnel-stub.sh")
	require.NoError(t, os.WriteFile(tunnelStub, []byte("#!/usr/bin/sh\nshift 3\nexec \"$@\"\n"), 0o755)) // #nosec G306 -- test script needs execute permission
	udsFile := filepath.Join(absTestDir, "proxy.sock")
	require.NoError(t, os.WriteFile(udsFile, nil, 0o600))
	cfg.FSRules = append(cfg.FSRules, roRule(tunnelStub), roRule(udsFile))
	bwrapPath, err := binutil.ResolveBwrap()
	require.NoError(t, err)
	wrapped := tunnel.WrapCommand(tunnelStub, udsFile, []string{"cat", testFile})
	sandboxCmd, cleanup, err := sandbox.Prepare(bwrapPath, cfg, wrapped, 3)
	require.NoError(t, err)
	defer cleanup()
	fullCommand := append([]string{sandboxCmd.BwrapPath}, sandboxCmd.Args...)

	// setupExecves=4 expects 4 execves, but only 3 occur (bwrap + tunnel stub + user command).
	// The monitor must still produce entries despite the incomplete chain.
	exitCode, err := runMonitorDirect(t, stracePath, logger, resolver, fullCommand, 4, sandboxCmd.ExtraFiles[0], nil, false)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := logBuf.String()
	assert.NotEmpty(t, logStr)

	// User command's file access must still appear despite incomplete execve chain
	assert.Contains(t, logStr, testFile)
	assert.Contains(t, logStr, "READ")
	assert.Contains(t, logStr, "OK")
}

func TestProcessStraceLine_BlockedSyscall_FileGroup(t *testing.T) {
	// mount is in the file trace group AND in ignoredSyscalls. When blockedSyscalls
	// is set, the syscall interception must catch it before the ignore list.
	assertBlockedSyscallEntry(t, "mount", `12345 mount("none", "/proc", "proc", 0) = -1 EPERM`)
}

// TestMonitor_CwdNotTrackedDuringSetup tests that AT_FDCWD annotations during
// bwrap setup don't populate cwdByPid. Only post-setup annotations are used.
func TestMonitor_CwdNotTrackedDuringSetup(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "project")
	require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".git/config"), []byte("[core]"), 0o600))

	hostDir := filepath.Join(tmpDir, "host")
	require.NoError(t, os.MkdirAll(filepath.Join(hostDir, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(hostDir, ".git/config"), []byte("[core]"), 0o600))

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(projectDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	mon, buf := createTestProcessor(t, cfg, 2)

	straceData := strings.NewReader(strings.Join([]string{
		// Setup phase — AT_FDCWD annotation should NOT be tracked
		`12345 execve("/usr/bin/bwrap", ""...) = 0`,
		`12345 openat(AT_FDCWD<` + hostDir + `>, "something", O_RDONLY) = 3`,
		// User command execve — ends setup phase
		`12345 execve("/usr/bin/git", ""...) = 0`,
		// Post-setup AT_FDCWD annotation — this IS tracked
		`12345 openat(AT_FDCWD<` + projectDir + `>, "src/main.go", O_RDONLY) = 3`,
		// Bare-path access should resolve using post-setup cwd
		`12345 access(".git/config", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(projectDir, ".git/config"), "OK")
	assert.NotContains(t, logStr, hostDir)
}

// TestMonitor_PerPidCwdIsolation tests that two pids with different cwds
// resolve bare-path calls to different absolute paths.
func TestMonitor_PerPidCwdIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	dirA := filepath.Join(tmpDir, "project-a")
	dirB := filepath.Join(tmpDir, "project-b")
	require.NoError(t, os.MkdirAll(filepath.Join(dirA, ".git"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(dirB, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dirA, ".git/config"), []byte("[core]"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dirB, ".git/config"), []byte("[core]"), 0o600))

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(dirA), roRule(dirB)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD<` + dirA + `>, "src/main.go", O_RDONLY) = 3`,
		`12346 openat(AT_FDCWD<` + dirB + `>, "src/main.go", O_RDONLY) = 3`,
		`12345 access(".git/config", R_OK) = 0`,
		`12346 access(".git/config", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(dirA, ".git/config"), "OK")
	assertLogContainsLine(t, logStr, "READ", filepath.Join(dirB, ".git/config"), "OK")
}

// TestMonitor_RelativeChdirJoinedWithExistingCwd tests that a relative chdir
// is joined with the existing tracked cwd.
func TestMonitor_RelativeChdirJoinedWithExistingCwd(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "sub")
	require.NoError(t, os.MkdirAll(subDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("data"), 0o600))

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(tmpDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		// Establish cwd via AT_FDCWD annotation
		`12345 openat(AT_FDCWD<` + tmpDir + `>, "file", O_RDONLY) = 3`,
		// Relative chdir joined with existing cwd
		`12345 chdir("sub") = 0`,
		// Bare-path access resolves against tmpDir/sub
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(subDir, "file.txt"), "OK", "ro:"+tmpDir)
}

// TestMonitor_RelativeChdirWithNoPriorCwdIgnored tests that a relative chdir
// from a pid with no tracked cwd is silently ignored.
func TestMonitor_RelativeChdirWithNoPriorCwdIgnored(t *testing.T) {
	cfg := new(config.Config)
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		// Relative chdir with no prior cwd — silently skipped
		`12345 chdir("sub") = 0`,
		// Bare-path access still produces UNKNOWN
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", "file.txt", "UNKNOWN", accesslog.RuleUnresolvedRelativePath)
}

// TestMonitor_FailedChdirDoesNotUpdateTrackedCwd tests that a failed chdir does not
// corrupt the tracked cwd, so subsequent bare-path accesses still resolve
// against the original cwd.
func TestMonitor_FailedChdirDoesNotUpdateTrackedCwd(t *testing.T) {
	tmpDir, mon, buf := createCwdTestProcessor(t)

	straceData := strings.NewReader(strings.Join([]string{
		// Establish cwd via AT_FDCWD annotation
		`12345 openat(AT_FDCWD<` + tmpDir + `>, "file.txt", O_RDONLY) = 3`,
		// Failed chdir — must not update tracked cwd
		`12345 chdir("/nonexistent") = -1 ENOENT (No such file or directory)`,
		// Bare-path access should still resolve against original cwd
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(tmpDir, "file.txt"), "OK", "ro:"+tmpDir)
}

// TestMonitor_FailedFchdirDoesNotUpdateTrackedCwd tests that a failed fchdir does not
// corrupt the tracked cwd, so subsequent bare-path accesses still resolve
// against the original cwd.
func TestMonitor_FailedFchdirDoesNotUpdateTrackedCwd(t *testing.T) {
	tmpDir, mon, buf := createCwdTestProcessor(t)

	straceData := strings.NewReader(strings.Join([]string{
		// Establish cwd via AT_FDCWD annotation
		`12345 openat(AT_FDCWD<` + tmpDir + `>, "file.txt", O_RDONLY) = 3`,
		// Failed fchdir — must not update tracked cwd
		`12345 fchdir(3</nonexistent>) = -1 EBADF (Bad file descriptor)`,
		// Bare-path access should still resolve against original cwd
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(tmpDir, "file.txt"), "OK", "ro:"+tmpDir)
}

// TestMonitor_FchdirWithoutAnnotationDoesNotUpdateCwd tests that fchdir without
// an fd path annotation (e.g., fchdir(3) instead of fchdir(3</path>)) does not
// update cwdByPid. When strace can't resolve the fd, the fchdirRegex won't match,
// so the line is silently skipped and subsequent bare-path calls remain UNKNOWN.
func TestMonitor_FchdirWithoutAnnotationDoesNotUpdateCwd(t *testing.T) {
	cfg := new(config.Config)
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		// fchdir with no <path> annotation — strace couldn't resolve the fd
		`12345 fchdir(3) = 0`,
		// Subsequent bare-path access has no tracked cwd → UNKNOWN
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", "file.txt", "UNKNOWN", accesslog.RuleUnresolvedRelativePath)
}

// TestMonitor_SetupPhaseEOFBeforeExpectedExecves tests that when EOF is reached
// before the expected number of execves (e.g., tunnel crashes before user command),
// the last execve seen is still processed and produces log entries.
func TestMonitor_SetupPhaseEOFBeforeExpectedExecves(t *testing.T) {
	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule("/usr")},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	// setupExecves=3 expects 3 execves, but we only provide 2
	mon, buf := createTestProcessor(t, cfg, 3)

	straceData := strings.NewReader(strings.Join([]string{
		// execve 1: bwrap
		`12345 execve("/usr/bin/bwrap", ""...) = 0`,
		// bwrap setup noise
		`12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 5`,
		// execve 2: tunnel binary (but no 3rd execve — tunnel crashed)
		`12345 execve("/usr/bin/ls", ""...) = 0`,
		// Lines after the last execve — these are consumed during the scan
		// and must be replayed by the caller. They represent the tunnel's
		// runtime activity (library loads, PATH lookups) before it crashed.
		`12345 openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY) = 3`,
		// EOF — no 3rd execve (user command never started)
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	require.NotEmpty(t, logStr)
	// The last execve should be processed as the best-effort user command
	assertLogContainsLine(t, logStr, "READ", "/usr/bin/ls")
	// Lines after the last execve should also be replayed and processed
	assertLogContainsLine(t, logStr, "READ", "/usr/lib/libc.so.6")
}
