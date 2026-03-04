package monitor

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
	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/syscallrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type monitorTestEnv struct {
	t          *testing.T
	TmpDir     string
	logBuf     bytes.Buffer
	logger     *accesslog.Logger
	stracePath string
	resolver   *fsrules.Resolver
}

func newMonitorTestEnv(t *testing.T, setupConfig func(tmpDir string) *config.Config) *monitorTestEnv {
	t.Helper()

	stracePath, err := binutil.ResolveStrace()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	cfg := setupConfig(tmpDir)

	env := &monitorTestEnv{
		t:      t,
		TmpDir: tmpDir,
	}

	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, ShowAllowed: true}
	env.logger = accesslog.New(&env.logBuf, logCfg)
	env.resolver = fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	env.stracePath = stracePath

	return env
}

func (e *monitorTestEnv) run(cmd []string) (int, error) {
	processor := New(e.logger, e.resolver, nil, 0, false)
	prepared, err := Prepare(e.stracePath, cmd, nil, nil, 3)
	if err != nil {
		return 1, err
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

	exitCode, exitErr := exitcode.Extract(waitErr)
	if exitErr != nil {
		return exitCode, exitErr
	}

	processingErr := <-processingErrCh
	if processingErr != nil {
		if !errors.Is(processingErr, os.ErrClosed) {
			return exitCode, processingErr
		}
	}

	return exitCode, nil
}

// readLog returns the text log output for assertions.
func (e *monitorTestEnv) readLog() string {
	e.t.Helper()
	logStr := e.logBuf.String()
	e.t.Logf("Log content:\n%s", logStr)
	return logStr
}

func (e *monitorTestEnv) logLines() []string {
	return strings.Split(strings.TrimSpace(e.readLog()), "\n")
}

func mustParseSyscallRule(t *testing.T, ruleBody string) syscallrules.Rule {
	t.Helper()
	rule, err := syscallrules.ParseRule(ruleBody, "")
	require.NoError(t, err)
	return rule
}

func roRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
		SourcePath: "",
	}
}

// createTestProcessor creates a Processor with a logger for testing.
// Returns the processor and the log buffer.
// setupExecves controls how many execves to skip in strace output.
func createTestProcessor(t *testing.T, cfg *config.Config, setupExecves int) (*Monitor, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, ShowAllowed: true}
	logger := accesslog.New(&buf, logCfg)
	fsResolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	return New(logger, fsResolver, nil, setupExecves, false), &buf
}

// createCwdTestProcessor creates a temp dir with a file.txt and a processor with a ro rule for it.
// Returns the temp dir, processor, and log buffer.
func createCwdTestProcessor(t *testing.T) (string, *Monitor, *bytes.Buffer) {
	t.Helper()
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("data"), 0o600))
	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(tmpDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	proc, buf := createTestProcessor(t, cfg, 0)
	return tmpDir, proc, buf
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

func rwRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "rw:" + path,
		SourcePath: "",
	}
}

// countLogLines returns the number of log entries in s (one per newline).
func countLogLines(s string) int {
	return strings.Count(s, "\n")
}

// countLinesContaining counts lines in s that contain substr.
func countLinesContaining(s, substr string) int {
	count := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			count++
		}
	}
	return count
}

func TestMonitor_Integration(t *testing.T) {
	var testFile string
	env := newMonitorTestEnv(t, func(tmpDir string) *config.Config {
		testFile = filepath.Join(tmpDir, "test.txt")
		err := os.WriteFile(testFile, []byte("test content"), 0o600)
		require.NoError(t, err)

		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(testFile)},
			NetRules:     nil,
			SyscallRules: nil,
			ManagedPaths: nil,

			ConfigPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assert.Contains(t, logStr, "READ")

	lines := env.logLines()
	assert.NotEmpty(t, lines)

	// Verify log format (operation, path, result, rule)
	for _, line := range lines {
		parts := strings.Fields(line)
		assert.GreaterOrEqual(t, len(parts), 4)
	}
}

func TestMonitor_DeniedAccess(t *testing.T) {
	var testFile string
	env := newMonitorTestEnv(t, func(tmpDir string) *config.Config {
		testFile = filepath.Join(tmpDir, "test.txt")
		err := os.WriteFile(testFile, []byte("test content"), 0o600)
		require.NoError(t, err)

		return new(config.Config)
	})

	_, _ = env.run([]string{"cat", testFile})

	logStr := env.readLog()
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, accesslog.RuleNoMatch)
}

func TestMonitor_WriteOperation(t *testing.T) {
	// Create a test directory outside /tmp (which is a managed path).
	// Use cwd-relative path to avoid being filtered by isManagedPath.
	//nolint:usetesting // intentionally not using t.TempDir() - we need a custom location
	testDir, err := os.MkdirTemp(".", "monitor-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	testFile := filepath.Join(absTestDir, "output.txt")

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			SyscallRules: nil,
			ManagedPaths: nil,

			ConfigPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "echo 'test' > " + testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assert.Contains(t, logStr, "WRITE")
	assert.NotEmpty(t, env.logLines())
}

func TestMonitor_Deduplication(t *testing.T) {
	var testFile string
	env := newMonitorTestEnv(t, func(tmpDir string) *config.Config {
		testFile = filepath.Join(tmpDir, "test.txt")
		err := os.WriteFile(testFile, []byte("line1\nline2\nline3\n"), 0o600)
		require.NoError(t, err)

		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(testFile)},
			NetRules:     nil,
			SyscallRules: nil,
			ManagedPaths: nil,

			ConfigPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "cat " + testFile + " && cat " + testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	require.Contains(t, logStr, testFile)
	assert.LessOrEqual(t, countLinesContaining(logStr, testFile), 1)
}

func TestMapSyscallToOperation(t *testing.T) {
	tests := []struct {
		name     string
		syscall  string
		line     string
		expected operationType
	}{
		{"open read", "open", `open("/file", O_RDONLY)`, operationRead},
		{"open write", "open", `open("/file", O_WRONLY)`, operationWrite},
		{"open rdwr", "open", `open("/file", O_RDWR)`, operationWrite},
		{"open create", "open", `open("/file", O_CREAT)`, operationWrite},
		// Filenames containing flag names should not cause misclassification
		{"open read file named O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/O_CREAT", O_RDONLY) = 3`, operationRead},
		{"open read file named O_WRONLY", "openat", `12345 openat(AT_FDCWD, "/tmp/O_WRONLY", O_RDONLY) = 3`, operationRead},
		{"open read file named O_RDWR", "openat", `12345 openat(AT_FDCWD, "/tmp/O_RDWR", O_RDONLY) = 3`, operationRead},
		{"open read path with O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/test_O_CREAT.txt", O_RDONLY) = 3`, operationRead},
		{"open write file named O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/O_CREAT", O_CREAT|O_WRONLY, 0644) = 3`, operationWrite},
		{"stat", "stat", `stat("/file")`, operationRead},
		{"fstatat", "fstatat", `fstatat(AT_FDCWD, "/file", ...)`, operationRead},
		{"newfstatat", "newfstatat", `newfstatat(AT_FDCWD, "/file", ...)`, operationRead},
		{"read", "read", `read(3, ...)`, operationRead},
		{"write", "write", `write(3, ...)`, operationWrite},
		{"unlink", "unlink", `unlink("/file")`, operationWrite},
		{"mkdir", "mkdir", `mkdir("/dir")`, operationWrite},
		{"chmod", "chmod", `chmod("/file", 0755)`, operationWrite},
		{"execve", "execve", `execve("/bin/sh")`, operationRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapSyscallToOperation(tt.syscall, tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMonitor_UnresolvedRelativePath tests that relative paths in strace output
// are logged with UNKNOWN result and unresolved-relative-path rule.
// Bare-path syscalls (e.g., access, readlink) don't have an fd argument, so strace
// cannot annotate them with a directory path. When no cwd has been tracked for the
// pid, these relative paths remain unresolved. AT_FDCWD without annotation (older
// strace) is another source but less common on modern systems.
func TestMonitor_UnresolvedRelativePath(t *testing.T) {
	cfg := new(config.Config)
	mon, buf := createTestProcessor(t, cfg, 0)

	// Synthetic strace output: openat with AT_FDCWD but no path resolution.
	// The relative path "foo/bar.txt" cannot be resolved to an absolute path.
	straceData := strings.NewReader(
		`12345 openat(AT_FDCWD, "foo/bar.txt", O_RDONLY) = -1 ENOENT (No such file or directory)` + "\n",
	)

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	assertLogContainsLine(t, logStr, "READ", "foo/bar.txt", "UNKNOWN", accesslog.RuleUnresolvedRelativePath)
}

// TestMonitor_SetupPhaseSkipped tests that bwrap setup lines are skipped
// until the user command's execve is detected.
func TestMonitor_SetupPhaseSkipped(t *testing.T) {
	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule("/usr")},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	// setupExecves=2 enables setup phase detection
	mon, buf := createTestProcessor(t, cfg, 2)

	// Synthetic strace output mimicking bwrap + user command sequence
	straceData := strings.NewReader(strings.Join([]string{
		// Setup phase (skipped)
		`12345 execve("/usr/bin/bwrap", ""...) = 0`,
		`12345 mkdirat(AT_FDCWD, "newroot", 0755) = 0`,
		`12345 openat(AT_FDCWD, "newroot/oldroot", O_RDONLY) = 3`,
		`12345 openat(3, "pts/ptmx", O_RDWR) = 4`,
		`12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 5`,
		// Transition: bwrap exec's user command
		`12345 execve("/usr/bin/cat", ""...) = 0`,
		// Active phase (processed)
		`12345 openat(AT_FDCWD</usr>, "lib/libc.so.6", O_RDONLY) = 3`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	// Setup operations should be skipped
	assert.NotContains(t, logStr, "newroot")
	assert.NotContains(t, logStr, "oldroot")
	assert.NotContains(t, logStr, "pts/ptmx")
	assert.NotContains(t, logStr, "bwrap")
	assert.NotContains(t, logStr, "ld.so.cache")

	// User command's execve and operations should be logged
	assert.Contains(t, logStr, "/usr/bin/cat")
	assert.Contains(t, logStr, "/usr/lib/libc.so.6")
}

// TestMonitor_NoSetupPhaseWithoutBwrap tests that setup phase detection is
// disabled when setupExecves is 0 (direct strace without bwrap).
func TestMonitor_NoSetupPhaseWithoutBwrap(t *testing.T) {
	cfg := new(config.Config)
	mon, buf := createTestProcessor(t, cfg, 0)

	// Without bwrap, all lines should be processed (no setup phase)
	straceData := strings.NewReader(strings.Join([]string{
		`12345 execve("/usr/bin/cat", ""...) = 0`,
		`12345 openat(AT_FDCWD, "foo/bar.txt", O_RDONLY) = -1 ENOENT`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	// All lines should be processed
	assert.Contains(t, logStr, "/usr/bin/cat")
	assert.Contains(t, logStr, "foo/bar.txt")
}

func TestBuildStraceArgs(t *testing.T) {
	args := buildStraceArgs([]string{"echo", "hello"}, 3, nil)

	// Should contain strace flags and original command
	assert.Contains(t, args, "-f")
	assert.Contains(t, args, "-y")
	assert.Contains(t, args, "trace=file,fchdir")
	assert.Contains(t, args, "-qq")
	assert.Contains(t, args, "/proc/self/fd/3")
	assert.Contains(t, args, "echo")
	assert.Contains(t, args, "hello")
}

func TestBuildStraceArgs_WithBlockedSyscalls(t *testing.T) {
	sr := syscallrules.NewResolver(
		[]syscallrules.Rule{mustParseSyscallRule(t, "allow:bpf")},
		seccomp.RuleableSyscallNames(),
	)
	args := buildStraceArgs([]string{"echo", "hello"}, 3, sr)

	// Find the trace= argument
	var traceArg string
	for _, a := range args {
		if strings.HasPrefix(a, "trace=") {
			traceArg = a
			break
		}
	}
	require.NotEmpty(t, traceArg)

	// Should include file,fchdir plus the sorted syscall names
	assert.Contains(t, traceArg, "file,fchdir")
	assert.Contains(t, traceArg, ",mount,")
	assert.Contains(t, traceArg, ",ptrace")
	assert.Contains(t, traceArg, ",bpf,")

	// bpf < mount < ptrace alphabetically
	assert.Less(t, strings.Index(traceArg, ",bpf,"), strings.Index(traceArg, ",mount,"))
	assert.Less(t, strings.Index(traceArg, ",mount,"), strings.Index(traceArg, ",ptrace"))
}

func TestBuildStraceArgs_WithoutBlockedSyscalls(t *testing.T) {
	args := buildStraceArgs([]string{"echo", "hello"}, 3, nil)

	// Find the trace= argument
	var traceArg string
	for _, a := range args {
		if strings.HasPrefix(a, "trace=") {
			traceArg = a
			break
		}
	}
	assert.Equal(t, "trace=file,fchdir", traceArg)
}

// assertBlockedSyscallEntry verifies that processing a strace line for a blocked syscall
// produces a single SYSCALL DENY entry with the expected target name.
func assertBlockedSyscallEntry(t *testing.T, syscallName, straceLine string) {
	t.Helper()
	sr := syscallrules.NewResolver(nil, seccomp.RuleableSyscallNames())
	cfg := new(config.Config)
	var buf bytes.Buffer
	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, ShowAllowed: true}
	logger := accesslog.New(&buf, logCfg)
	fsResolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	mon := New(logger, fsResolver, sr, 0, false)

	err := mon.Run(strings.NewReader(straceLine + "\n"))
	require.NoError(t, err)

	logStr := buf.String()
	require.Equal(t, 1, countLogLines(logStr))
	assert.Contains(t, logStr, "SYSCALL")
	assert.Contains(t, logStr, syscallName)
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, "("+accesslog.RuleNoMatch+")")
}

func TestProcessStraceLine_BlockedSyscall(t *testing.T) {
	assertBlockedSyscallEntry(t, "ptrace", `12345 ptrace(PTRACE_ATTACH, 999) = -1 EPERM (Operation not permitted)`)
}

func TestProcessStraceLine_BlockedSyscall_FileGroup(t *testing.T) {
	// mount is in the file trace group AND in ignoredSyscalls. When blockedSyscalls
	// is set, the syscall interception must catch it before the ignore list.
	assertBlockedSyscallEntry(t, "mount", `12345 mount("none", "/proc", "proc", 0) = -1 EPERM`)
}

func TestProcessStraceLine_AllowedSyscall(t *testing.T) {
	sr := syscallrules.NewResolver(
		[]syscallrules.Rule{mustParseSyscallRule(t, "allow:ptrace")},
		seccomp.RuleableSyscallNames(),
	)
	cfg := new(config.Config)
	var buf bytes.Buffer
	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, ShowAllowed: true}
	logger := accesslog.New(&buf, logCfg)
	fsResolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	mon := New(logger, fsResolver, sr, 0, false)

	straceData := strings.NewReader(
		`12345 ptrace(PTRACE_ATTACH, 999) = 0` + "\n",
	)

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := buf.String()
	require.Equal(t, 1, countLogLines(logStr))
	assert.Contains(t, logStr, "SYSCALL")
	assert.Contains(t, logStr, "ptrace")
	assert.Contains(t, logStr, "OK")
	assert.Contains(t, logStr, "(allow:ptrace)")
}

func TestBuildStraceArgs_CommandPassthrough(t *testing.T) {
	// Verify that a command with --seccomp args passes through to strace args correctly.
	command := []string{"/usr/bin/bwrap", "--seccomp", "4", "--unshare-all", "--", "true"}
	args := buildStraceArgs(command, 3, nil)

	// --seccomp 4 should appear in the strace args (bwrap section)
	found := false
	for i, a := range args {
		if a == "--seccomp" && i+1 < len(args) && args[i+1] == "4" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestBuildStraceArgs_NoSeccompWhenAbsent(t *testing.T) {
	command := []string{"/usr/bin/bwrap", "--unshare-all", "--", "true"}
	args := buildStraceArgs(command, 3, nil)

	for i, a := range args {
		if a == "--seccomp" {
			t.Errorf("unexpected --seccomp at index %d", i)
		}
	}
}

// testSymlinkAccessHelper sets up a symlink test scenario and validates the access log.
func testSymlinkAccessHelper(
	t *testing.T,
	configRules []fsrules.Rule,
	straceFlags string,
	expectedHopOp, expectedTargetOp string,
) {
	t.Helper()
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	err := os.MkdirAll(testBase, 0o700)
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(testBase) }()

	linkPath := filepath.Join(testBase, "link.txt")
	targetPath := filepath.Join(testBase, "target.txt")

	err = os.WriteFile(targetPath, []byte("test"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(targetPath, linkPath)
	require.NoError(t, err)

	cfg := &config.Config{FSRules: configRules}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + linkPath + `", ` + straceFlags + `) = 3`,
	}, "\n") + "\n")

	err = mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	assertLogContainsLine(t, logStr, expectedHopOp, linkPath, "OK")
	assertLogContainsLine(t, logStr, expectedTargetOp, targetPath, "OK")
}

func TestMonitor_SymlinkWithinMount(t *testing.T) {
	// Use /home prefix to avoid /tmp managed path filtering
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	testSymlinkAccessHelper(t, []fsrules.Rule{roRule(testBase)}, "O_RDONLY", "READ", "READ")
}

func TestMonitor_SymlinkDeniedTarget(t *testing.T) {
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	err := os.MkdirAll(testBase, 0o700)
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(testBase) }()

	mountDir := filepath.Join(testBase, "mount")
	outsideDir := filepath.Join(testBase, "outside")

	err = os.Mkdir(mountDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(outsideDir, 0o700)
	require.NoError(t, err)

	linkPath := filepath.Join(mountDir, "escape.txt")
	targetPath := filepath.Join(outsideDir, "secret.txt")

	err = os.WriteFile(targetPath, []byte("secret"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(targetPath, linkPath)
	require.NoError(t, err)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(mountDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + linkPath + `", O_RDONLY) = -1 EACCES`,
	}, "\n") + "\n")

	err = mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	// Hop should be OK, target should be denied
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK")
	assertLogContainsLine(t, logStr, "READ", targetPath, "DENY")
}

func TestMonitor_SymlinkWriteOperation(t *testing.T) {
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	testSymlinkAccessHelper(t, []fsrules.Rule{rwRule(testBase)}, "O_WRONLY", "READ", "WRITE")
}

func TestMonitor_SymlinkWriteThroughReadOnlyLink(t *testing.T) {
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	err := os.MkdirAll(testBase, 0o700)
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(testBase) }()

	roDir := filepath.Join(testBase, "readonly")
	rwDir := filepath.Join(testBase, "writable")

	err = os.Mkdir(roDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(rwDir, 0o700)
	require.NoError(t, err)

	linkPath := filepath.Join(roDir, "link.txt")
	targetPath := filepath.Join(rwDir, "target.txt")

	err = os.WriteFile(targetPath, []byte("test"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(targetPath, linkPath)
	require.NoError(t, err)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(roDir), rwRule(rwDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + linkPath + `", O_WRONLY) = 3`,
	}, "\n") + "\n")

	err = mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	// Hop is READ (symlink in ro dir), target is WRITE (in rw dir)
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK")
	assertLogContainsLine(t, logStr, "WRITE", targetPath, "OK")
}

func TestMonitor_SymlinkThroughManagedPath(t *testing.T) {
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	mountDir := filepath.Join(testBase, "mount")
	managedDir := filepath.Join(testBase, "managed")

	err := os.MkdirAll(mountDir, 0o700)
	require.NoError(t, err)
	err = os.MkdirAll(managedDir, 0o700)
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(testBase) }()

	linkPath := filepath.Join(mountDir, "link.txt")
	managedTarget := filepath.Join(managedDir, "target.txt")

	err = os.WriteFile(managedTarget, []byte("data"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(managedTarget, linkPath)
	require.NoError(t, err)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{rwRule(mountDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: []string{managedDir},

		ConfigPaths: nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(
		`12345 openat(AT_FDCWD, "` + linkPath + `", O_RDONLY) = 3` + "\n",
	)

	err = mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)

	// Original path should be logged as UNKNOWN since symlink target is in managed area
	assertLogContainsLine(t, logStr, "READ", linkPath, "UNKNOWN", accesslog.RuleSymlinkTargetUnresolvable)
}

func TestMonitor_SymlinkTargetDeduplicated(t *testing.T) {
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	err := os.MkdirAll(testBase, 0o700)
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(testBase) }()

	link1 := filepath.Join(testBase, "link1")
	link2 := filepath.Join(testBase, "link2")
	targetPath := filepath.Join(testBase, "target.txt")

	err = os.WriteFile(targetPath, []byte("test"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(targetPath, link1)
	require.NoError(t, err)
	err = os.Symlink(targetPath, link2)
	require.NoError(t, err)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(testBase)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + link1 + `", O_RDONLY) = 3`,
		`12345 openat(AT_FDCWD, "` + link2 + `", O_RDONLY) = 3`,
	}, "\n") + "\n")

	err = mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assert.Equal(t, 1, countLinesContaining(logStr, targetPath))
}

// formatEntries returns the log buffer contents for assertions.
func formatEntries(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	logStr := buf.String()
	t.Logf("Log content:\n%s", logStr)
	return logStr
}

// TestMonitor_CwdTrackingResolvesBarePath tests that AT_FDCWD annotations
// establish per-pid cwd, allowing subsequent bare-path relative syscalls
// to be resolved to absolute paths.
func TestMonitor_CwdTrackingResolvesBarePath(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]"), 0o600))

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{roRule(tmpDir)},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(strings.Join([]string{
		// AT_FDCWD annotation establishes cwd for pid 12345
		`12345 openat(AT_FDCWD<` + tmpDir + `>, "src/main.go", O_RDONLY) = 3`,
		// Bare-path access from same pid — should resolve using tracked cwd
		`12345 access(".git/config", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(tmpDir, ".git/config"), "OK", "ro:"+tmpDir)
}

// TestMonitor_NoCwdForPidStillUnresolved tests that bare-path syscalls from
// a pid with no prior AT_FDCWD/chdir/fchdir produce UNKNOWN entries.
func TestMonitor_NoCwdForPidStillUnresolved(t *testing.T) {
	cfg := new(config.Config)
	mon, buf := createTestProcessor(t, cfg, 0)

	straceData := strings.NewReader(
		`12345 access("foo/bar.txt", R_OK) = -1 ENOENT` + "\n",
	)

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", "foo/bar.txt", "UNKNOWN", accesslog.RuleUnresolvedRelativePath)
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

		ConfigPaths: nil,
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

		ConfigPaths: nil,
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

// TestMonitor_ChdirUpdatesTrackedCwd tests that chdir with an absolute path
// updates cwdByPid and subsequent bare-path calls resolve correctly.
func TestMonitor_ChdirUpdatesTrackedCwd(t *testing.T) {
	tmpDir, mon, buf := createCwdTestProcessor(t)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 chdir("` + tmpDir + `") = 0`,
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(tmpDir, "file.txt"), "OK", "ro:"+tmpDir)
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

		ConfigPaths: nil,
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

		ConfigPaths: nil,
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

// TestMonitor_FchdirUpdatesTrackedCwd tests that fchdir with an fd-annotated
// path updates cwdByPid and subsequent bare-path calls resolve correctly.
func TestMonitor_FchdirUpdatesTrackedCwd(t *testing.T) {
	tmpDir, mon, buf := createCwdTestProcessor(t)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 fchdir(3<` + tmpDir + `>) = 0`,
		`12345 access("file.txt", R_OK) = 0`,
	}, "\n") + "\n")

	err := mon.Run(straceData)
	require.NoError(t, err)

	logStr := formatEntries(t, buf)
	assertLogContainsLine(t, logStr, "READ", filepath.Join(tmpDir, "file.txt"), "OK", "ro:"+tmpDir)
}
