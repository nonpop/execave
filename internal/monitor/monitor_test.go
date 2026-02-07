package monitor_test

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type monitorTestEnv struct {
	t       *testing.T
	TmpDir  string
	LogPath string
	mon     *monitor.Monitor
}

func newMonitorTestEnv(t *testing.T, cfg *config.Config) *monitorTestEnv {
	t.Helper()
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "access.log")
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	return &monitorTestEnv{
		t:       t,
		TmpDir:  tmpDir,
		LogPath: logPath,
		mon:     mon,
	}
}

func (e *monitorTestEnv) createFile(name, content string) string {
	e.t.Helper()
	path := filepath.Join(e.TmpDir, name)
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(e.t, err)
	return path
}

func (e *monitorTestEnv) run(cmd []string) (int, error) {
	return e.mon.Run(context.Background(), cmd) //nolint:wrapcheck
}

func (e *monitorTestEnv) readLog() string {
	e.t.Helper()
	content, err := os.ReadFile(e.LogPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(e.t, err)
	logStr := string(content)
	e.t.Logf("Log content:\n%s", logStr)
	return logStr
}

func (e *monitorTestEnv) logLines() []string {
	return strings.Split(strings.TrimSpace(e.readLog()), "\n")
}

func roRule(path string) config.Rule {
	return config.Rule{
		Resource:   config.ResourceFS,
		Permission: config.PermissionReadOnly,
		Path:       path,
		RawRule:    "fs:ro:" + path,
	}
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

func rwRule(path string) config.Rule {
	return config.Rule{
		Resource:   config.ResourceFS,
		Permission: config.PermissionReadWrite,
		Path:       path,
		RawRule:    "fs:rw:" + path,
	}
}

func TestMonitor_Integration(t *testing.T) {
	cfg := new(config.Config)
	env := newMonitorTestEnv(t, cfg)
	testFile := env.createFile("test.txt", "test content")

	// Add rule after env creation to use testFile path
	env.mon = monitor.New(env.LogPath, rules.New(&config.Config{
		Rules:        []config.Rule{roRule(testFile)},
		ManagedPaths: nil,
	}), nil)

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
	cfg := new(config.Config)
	env := newMonitorTestEnv(t, cfg)
	testFile := env.createFile("test.txt", "test content")

	_, _ = env.run([]string{"cat", testFile})

	logStr := env.readLog()
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, monitor.ExportedRuleNoMatch)
}

func TestMonitor_WriteOperation(t *testing.T) {
	cfg := new(config.Config)
	env := newMonitorTestEnv(t, cfg)

	// Create a test directory outside /tmp (which is a managed path).
	// Use cwd-relative path to avoid being filtered by isManagedPath.
	//nolint:usetesting // intentionally not using t.TempDir() - we need a custom location
	testDir, err := os.MkdirTemp(".", "monitor-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	testFile := filepath.Join(absTestDir, "output.txt")

	env.mon = monitor.New(env.LogPath, rules.New(&config.Config{
		Rules:        []config.Rule{rwRule(absTestDir)},
		ManagedPaths: nil,
	}), nil)

	exitCode, err := env.run([]string{"sh", "-c", "echo 'test' > " + testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assert.Contains(t, logStr, "WRITE")
	assert.NotEmpty(t, env.logLines())
}

func TestMonitor_Deduplication(t *testing.T) {
	cfg := new(config.Config)
	env := newMonitorTestEnv(t, cfg)
	testFile := env.createFile("test.txt", "line1\nline2\nline3\n")

	env.mon = monitor.New(env.LogPath, rules.New(&config.Config{
		Rules:        []config.Rule{roRule(testFile)},
		ManagedPaths: nil,
	}), nil)

	exitCode, err := env.run([]string{"sh", "-c", "cat " + testFile + " && cat " + testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logFile, err := os.Open(env.LogPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	scanner := bufio.NewScanner(logFile)
	pathCounts := make(map[string]int)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 {
			pathCounts[parts[1]]++
		}
	}

	t.Logf("Path counts: %v", pathCounts)

	// Each path should appear at most once (deduplication)
	for _, count := range pathCounts {
		assert.LessOrEqual(t, count, 1)
	}
}

func TestMapSyscallToOperation(t *testing.T) {
	tests := []struct {
		name     string
		syscall  string
		line     string
		expected monitor.OperationType
	}{
		{"open read", "open", `open("/file", O_RDONLY)`, monitor.OperationRead},
		{"open write", "open", `open("/file", O_WRONLY)`, monitor.OperationWrite},
		{"open rdwr", "open", `open("/file", O_RDWR)`, monitor.OperationWrite},
		{"open create", "open", `open("/file", O_CREAT)`, monitor.OperationWrite},
		// Filenames containing flag names should not cause misclassification
		{"open read file named O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/O_CREAT", O_RDONLY) = 3`, monitor.OperationRead},
		{"open read file named O_WRONLY", "openat", `12345 openat(AT_FDCWD, "/tmp/O_WRONLY", O_RDONLY) = 3`, monitor.OperationRead},
		{"open read file named O_RDWR", "openat", `12345 openat(AT_FDCWD, "/tmp/O_RDWR", O_RDONLY) = 3`, monitor.OperationRead},
		{"open read path with O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/test_O_CREAT.txt", O_RDONLY) = 3`, monitor.OperationRead},
		{"open write file named O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/O_CREAT", O_CREAT|O_WRONLY, 0644) = 3`, monitor.OperationWrite},
		{"stat", "stat", `stat("/file")`, monitor.OperationRead},
		{"fstatat", "fstatat", `fstatat(AT_FDCWD, "/file", ...)`, monitor.OperationRead},
		{"newfstatat", "newfstatat", `newfstatat(AT_FDCWD, "/file", ...)`, monitor.OperationRead},
		{"read", "read", `read(3, ...)`, monitor.OperationRead},
		{"write", "write", `write(3, ...)`, monitor.OperationWrite},
		{"unlink", "unlink", `unlink("/file")`, monitor.OperationWrite},
		{"mkdir", "mkdir", `mkdir("/dir")`, monitor.OperationWrite},
		{"chmod", "chmod", `chmod("/file", 0755)`, monitor.OperationWrite},
		{"execve", "execve", `execve("/bin/sh")`, monitor.OperationRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := monitor.MapSyscallToOperation(tt.syscall, tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMonitor_UnresolvedRelativePath tests that relative paths in strace output
// are logged with UNKNOWN result and unresolved-relative-path rule.
// Uses synthetic strace data because triggering unresolved relative paths in real
// strace requires older strace versions (< 5.2) that don't resolve AT_FDCWD with -y.
func TestMonitor_UnresolvedRelativePath(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "access.log")
	cfg := new(config.Config)
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	// Synthetic strace output: openat with AT_FDCWD but no path resolution (older strace -y behavior).
	// The relative path "foo/bar.txt" cannot be resolved to an absolute path.
	straceData := strings.NewReader(
		`12345 openat(AT_FDCWD, "foo/bar.txt", O_RDONLY) = -1 ENOENT (No such file or directory)` + "\n",
	)

	logFile, err := os.Create(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	data, err := os.ReadFile(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

	assertLogContainsLine(t, logStr, "READ", "foo/bar.txt", "UNKNOWN", monitor.ExportedRuleUnresolvedRelativePath)
}

// TestMonitor_SetupPhaseSkipped tests that bwrap setup lines are skipped
// until the user command's execve is detected.
func TestMonitor_SetupPhaseSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "access.log")
	resolver := rules.New(&config.Config{
		Rules:        []config.Rule{roRule("/usr")},
		ManagedPaths: nil,
	})
	// Non-nil bwrapArgs enables setup phase detection
	mon := monitor.New(logPath, resolver, []string{"--ro-bind", "/usr", "/usr"})

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

	logFile, err := os.Create(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	data, err := os.ReadFile(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

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
// disabled when bwrapArgs is nil (direct strace without bwrap).
func TestMonitor_NoSetupPhaseWithoutBwrap(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "access.log")
	cfg := new(config.Config)
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	// Without bwrap, all lines should be processed (no setup phase)
	straceData := strings.NewReader(strings.Join([]string{
		`12345 execve("/usr/bin/cat", ""...) = 0`,
		`12345 openat(AT_FDCWD, "foo/bar.txt", O_RDONLY) = -1 ENOENT`,
	}, "\n") + "\n")

	logFile, err := os.Create(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	data, err := os.ReadFile(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

	// All lines should be processed
	assert.Contains(t, logStr, "/usr/bin/cat")
	assert.Contains(t, logStr, "foo/bar.txt")
}

func TestBuildStraceArgs(t *testing.T) {
	mon := monitor.New("/tmp/test.log", nil, nil)

	args := mon.BuildStraceArgs("/tmp/strace.out", []string{"echo", "hello"})

	// Should contain strace flags and original command
	assert.Contains(t, args, "-f")
	assert.Contains(t, args, "-y")
	assert.Contains(t, args, "trace=file")
	assert.Contains(t, args, "-qq")
	assert.Contains(t, args, "/tmp/strace.out")
	assert.Contains(t, args, "echo")
	assert.Contains(t, args, "hello")
}

func TestIsManagedPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Managed paths (infrastructure + bwrap internal)
		{"proc root", "/proc", true},
		{"proc file", "/proc/self/status", true},
		{"dev root", "/dev", true},
		{"dev file", "/dev/null", true},
		{"tmp root", "/tmp", true},
		{"tmp file", "/tmp/test.txt", true},
		{"newroot", "/newroot", true},
		{"newroot subdir", "/newroot/dev", true},
		{"oldroot", "/oldroot", true},
		{"oldroot subdir", "/oldroot/proc/self/fd/5", true},

		// Non-managed paths (user can configure rules)
		{"usr", "/usr", false},
		{"home", "/home", false},
		{"etc", "/etc", false},
		{"root", "/", false},
		{"usr bin", "/usr/bin/bash", false},
		{"home user", "/home/user/file.txt", false},
		{"uid_map in project", "/home/user/uid_map", false},
		{"ns dir in project", "/home/user/project/ns/config", false},
		{"self dir in project", "/home/user/self/fd", false},
		{"newroot dir in project", "/home/user/newroot", false},
		{"oldroot dir in project", "/home/user/oldroot", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := monitor.IsManagedPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// testSymlinkAccessHelper sets up a symlink test scenario and validates the access log.
func testSymlinkAccessHelper(
	t *testing.T,
	configRules []config.Rule,
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

	cfg := &config.Config{Rules: configRules, ManagedPaths: nil}
	logPath := filepath.Join(t.TempDir(), "access.log")
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + linkPath + `", ` + straceFlags + `) = 3`,
	}, "\n") + "\n")

	//nolint:gosec // Test code with controlled file path
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	//nolint:gosec // Test code with controlled file path
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

	assertLogContainsLine(t, logStr, expectedHopOp, linkPath, "OK")
	assertLogContainsLine(t, logStr, expectedTargetOp, targetPath, "OK")
}

func TestMonitor_SymlinkWithinMount(t *testing.T) {
	// Use /home prefix to avoid /tmp managed path filtering
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	testSymlinkAccessHelper(t, []config.Rule{roRule(testBase)}, "O_RDONLY", "READ", "READ")
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
		Rules:        []config.Rule{roRule(mountDir)},
		ManagedPaths: nil,
	}
	logPath := filepath.Join(t.TempDir(), "access.log")
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + linkPath + `", O_RDONLY) = -1 EACCES`,
	}, "\n") + "\n")

	//nolint:gosec // Test code with controlled file path
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	//nolint:gosec // Test code with controlled file path
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

	// Hop should be OK, target should be denied
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK")
	assertLogContainsLine(t, logStr, "READ", targetPath, "DENY")
}

func TestMonitor_SymlinkWriteOperation(t *testing.T) {
	testBase := filepath.Join(os.Getenv("HOME"), ".execave-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	testSymlinkAccessHelper(t, []config.Rule{rwRule(testBase)}, "O_WRONLY", "READ", "WRITE")
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
		Rules:        []config.Rule{roRule(roDir), rwRule(rwDir)},
		ManagedPaths: nil,
	}
	logPath := filepath.Join(t.TempDir(), "access.log")
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + linkPath + `", O_WRONLY) = 3`,
	}, "\n") + "\n")

	//nolint:gosec // Test code with controlled file path
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	//nolint:gosec // Test code with controlled file path
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

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
		Rules:        []config.Rule{rwRule(mountDir)},
		ManagedPaths: []string{managedDir},
	}
	logPath := filepath.Join(t.TempDir(), "access.log")
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	straceData := strings.NewReader(
		`12345 openat(AT_FDCWD, "` + linkPath + `", O_RDONLY) = 3` + "\n",
	)

	//nolint:gosec // Test code with controlled file path
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	//nolint:gosec // Test code with controlled file path
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

	// Original path should be logged as UNKNOWN since symlink target is in managed area
	assertLogContainsLine(t, logStr, "READ", linkPath, "UNKNOWN", monitor.ExportedRuleSymlinkTargetUnresolvable)
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
		Rules:        []config.Rule{roRule(testBase)},
		ManagedPaths: nil,
	}
	logPath := filepath.Join(t.TempDir(), "access.log")
	resolver := rules.New(cfg)
	mon := monitor.New(logPath, resolver, nil)

	straceData := strings.NewReader(strings.Join([]string{
		`12345 openat(AT_FDCWD, "` + link1 + `", O_RDONLY) = 3`,
		`12345 openat(AT_FDCWD, "` + link2 + `", O_RDONLY) = 3`,
	}, "\n") + "\n")

	//nolint:gosec // Test code with controlled file path
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	err = mon.ProcessStraceOutput(straceData, logFile)
	require.NoError(t, err)
	require.NoError(t, logFile.Close())

	//nolint:gosec // Test code with controlled file path
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logStr := string(data)
	t.Logf("Log content:\n%s", logStr)

	// Target should appear only once
	lines := strings.Split(strings.TrimSpace(logStr), "\n")
	targetCount := 0
	for _, line := range lines {
		if strings.Contains(line, targetPath) {
			targetCount++
		}
	}
	assert.Equal(t, 1, targetCount)
}
