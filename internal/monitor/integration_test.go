package monitor_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/seccomp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Real-time access log writing ---

func TestIntegration_RealTimeAccessLogWriting_LogEntriesAvailableDuringExecution(t *testing.T) {
	// Use a directory outside /tmp to avoid managed path filtering
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	dataDir := filepath.Join(absTestDir, "data")
	testFile := filepath.Join(dataDir, "file.txt")
	require.NoError(t, os.MkdirAll(dataDir, 0o750))
	require.NoError(t, os.WriteFile(testFile, []byte("test data"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(dataDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Run a command that reads the file, then sleeps briefly before exiting.
	// We verify entries appear during the sleep (while the sandbox is still running).
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = env.mon.Run(context.Background(), []string{"sh", "-c", "cat " + testFile + " && sleep 3"})
	}()

	// Entry must be available via the Logger while the sandbox is still running
	require.Eventually(t, func() bool {
		for _, e := range env.logger.Entries() {
			if e.Target == testFile && e.Operation == accesslog.OperationRead {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond)

	// Confirm the command is still running (still in the sleep phase)
	select {
	case <-done:
		t.Fatal("command exited before entry could be verified during execution")
	default:
	}

	// Verify entry fields
	for _, e := range env.logger.Entries() {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+dataDir, e.Rule)
		}
	}

	// Wait for command to finish normally
	<-done
}

// --- Requirement: Operation type mapping ---

func TestIntegration_OperationTypeMapping_QueryingFileMetadataLoggedAsRead(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	testFile := filepath.Join(absTestDir, "data.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// stat triggers statx/newfstatat which map directly to READ via syscallOperationMap.
	exitCode, err := env.run([]string{"stat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, found)
}

func TestIntegration_OperationTypeMapping_CreatingDirectoryLoggedAsWrite(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	newDir := filepath.Join(absTestDir, "newdir")

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{rwRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// mkdir triggers mkdirat which maps directly to WRITE via syscallOperationMap.
	exitCode, err := env.run([]string{"mkdir", newDir})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == newDir && e.Operation == accesslog.OperationWrite {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, found)
}

func TestIntegration_OperationTypeMapping_ReadingFileContentsLoggedAsRead(t *testing.T) {
	absTestDir, testFile := testDirWithFile(t, "data.txt", "content")
	env := roRuleEnv(t, absTestDir)

	// cat triggers openat(O_RDONLY) — classified as READ by classifyOpenOperation.
	exitCode, err := env.run([]string{"cat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assertHasReadEntry(t, env.logger.Entries(), testFile)
}

func TestIntegration_OperationTypeMapping_WritingFileContentsLoggedAsWrite(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	testFile := filepath.Join(absTestDir, "output.txt")

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{rwRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Shell redirection triggers openat(O_WRONLY|O_CREAT|O_TRUNC) — classified
	// as WRITE by classifyOpenOperation.
	exitCode, err := env.run([]string{"sh", "-c", "echo data > " + testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == testFile && e.Operation == accesslog.OperationWrite {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, found, "openat(O_WRONLY|O_CREAT) must be classified as WRITE")
}

// --- Requirement: Path resolution for *at() syscalls ---

// TestIntegration_PathResolutionForAtSyscalls_UnresolvedRelativePathLogged cannot be
// implemented as an integration test. The scenario requires strace to output an *at()
// syscall with an unresolved fd (no <path> decoration), which only happens with strace
// versions older than 5.2 that don't resolve AT_FDCWD with -y. Modern strace always
// resolves AT_FDCWD. The behavior is covered by unit test TestMonitor_UnresolvedRelativePath
// using synthetic strace data.
func TestIntegration_PathResolutionForAtSyscalls_UnresolvedRelativePathLogged(t *testing.T) {
	t.Skip("requires strace to leave AT_FDCWD unresolved — not possible with modern strace -y; covered by unit test")
}

// --- Requirement: Symlink path resolution in access logging ---

func TestIntegration_SymlinkPathResolutionInAccessLogging_RuleBoundarySymlinkLoggedWithoutResolution(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a real directory with a file
	realDir := filepath.Join(absTestDir, "real")
	require.NoError(t, os.MkdirAll(realDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("content"), 0o600))

	// Create a symlink to the real directory
	linkDir := filepath.Join(absTestDir, "link")
	require.NoError(t, os.Symlink(realDir, linkDir))

	// Rule at the symlink path — makes it a rule boundary.
	// The resolver skips symlink resolution for rule boundaries because
	// bwrap resolves these at mount time.
	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(linkDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Read a file through the symlink
	linkFile := filepath.Join(linkDir, "file.txt")
	realFile := filepath.Join(realDir, "file.txt")
	exitCode, err := env.run([]string{"cat", linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The entry must use the symlink (unresolved) path
	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+linkDir, e.Rule)
		}
	}
	assert.True(t, found)

	// The real (resolved) path must NOT appear in the log
	for _, e := range env.logger.Entries() {
		assert.NotEqual(t, realFile, e.Target)
	}
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_RuleBoundarySymlinkInIntermediateComponentLoggedWithoutResolution(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a real directory with a nested subdirectory and file
	realDir := filepath.Join(absTestDir, "real")
	subDir := filepath.Join(realDir, "sub")
	require.NoError(t, os.MkdirAll(subDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("content"), 0o600))

	// Create a symlink to the real directory — this symlink is an intermediate
	// path component when accessing link/sub/file.txt
	linkDir := filepath.Join(absTestDir, "link")
	require.NoError(t, os.Symlink(realDir, linkDir))

	// Rule at the symlink path — makes it a rule boundary.
	// The resolver skips the symlink; the kernel follows it transparently.
	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(linkDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Read a file two levels deep through the symlink
	linkFile := filepath.Join(linkDir, "sub", "file.txt")
	realFile := filepath.Join(realDir, "sub", "file.txt")
	exitCode, err := env.run([]string{"cat", linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The entry must use the symlink (unresolved) path
	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+linkDir, e.Rule)
		}
	}
	assert.True(t, found)

	// The real (resolved) path must NOT appear in the log
	for _, e := range env.logger.Entries() {
		assert.NotEqual(t, realFile, e.Target)
	}
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_SymlinkWithinMountResolvedAndLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a directory with a real file and a symlink to it
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	targetFile := filepath.Join(mountDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))
	linkFile := filepath.Join(mountDir, "link.txt")
	require.NoError(t, os.Symlink(targetFile, linkFile))

	// Rule at the mount directory — the symlink is a descendant, not a rule boundary,
	// so the resolver walks the host FS and resolves it.
	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	exitCode, err := env.run([]string{"cat", linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The symlink hop must be logged as a READ
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+mountDir, e.Rule)
		}
	}
	assert.True(t, hopFound)

	// The resolved target must be logged as a READ (the original operation)
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationRead {
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+mountDir, e.Rule)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_RelativeSymlinkWithinMountResolvedAndLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a directory with a real file and a relative symlink to it
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	targetFile := filepath.Join(mountDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))
	linkFile := filepath.Join(mountDir, "link.txt")
	// Relative target — resolver joins parent dir (mountDir) with "target.txt"
	require.NoError(t, os.Symlink("target.txt", linkFile))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	exitCode, err := env.run([]string{"cat", linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The symlink hop must be logged as a READ
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+mountDir, e.Rule)
		}
	}
	assert.True(t, hopFound)

	// The resolved target must be logged as a READ (the original operation)
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationRead {
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+mountDir, e.Rule)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_RelativeSymlinkChainResolvedWithAllHopsLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a directory with a chain: a.txt → b.txt → target.txt (all relative)
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	targetFile := filepath.Join(mountDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))
	bLink := filepath.Join(mountDir, "b.txt")
	require.NoError(t, os.Symlink("target.txt", bLink))
	aLink := filepath.Join(mountDir, "a.txt")
	require.NoError(t, os.Symlink("b.txt", aLink))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	exitCode, err := env.run([]string{"cat", aLink})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// Both hops must be logged as READ
	var aFound, bFound, targetFound bool
	for _, entry := range env.logger.Entries() {
		switch {
		case entry.Target == aLink && entry.Operation == accesslog.OperationRead:
			aFound = true
			assert.Equal(t, accesslog.ResultOK, entry.Result)
		case entry.Target == bLink && entry.Operation == accesslog.OperationRead:
			bFound = true
			assert.Equal(t, accesslog.ResultOK, entry.Result)
		case entry.Target == targetFile && entry.Operation == accesslog.OperationRead:
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, entry.Result)
		}
	}
	assert.True(t, aFound)
	assert.True(t, bFound)
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_SymlinkWithinMountPointingOutsideRulesDenied(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a ruled directory and an unruled directory
	mountDir := filepath.Join(absTestDir, "mount")
	unruledDir := filepath.Join(absTestDir, "unruled")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.MkdirAll(unruledDir, 0o750))
	unruledFile := filepath.Join(unruledDir, "secret.txt")
	require.NoError(t, os.WriteFile(unruledFile, []byte("secret"), 0o600))

	// Symlink inside ruled dir points to unruled path
	linkFile := filepath.Join(mountDir, "link.txt")
	require.NoError(t, os.Symlink(unruledFile, linkFile))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	_, err = env.run([]string{"sh", "-c", "cat " + linkFile + " || true"})
	require.NoError(t, err)

	// The hop must be logged as READ OK (symlink itself is in ruled dir)
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, hopFound)

	// The target must be logged as READ DENY (no matching rule)
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == unruledFile && e.Operation == accesslog.OperationRead {
			targetFound = true
			assert.Equal(t, accesslog.ResultDeny, e.Result)
			assert.Equal(t, accesslog.RuleNoMatch, e.Rule)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_MultiHopSymlinkChainWithinMount(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a chain with absolute targets: a.txt → b.txt → target.txt
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	targetFile := filepath.Join(mountDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))
	bLink := filepath.Join(mountDir, "b.txt")
	require.NoError(t, os.Symlink(targetFile, bLink))
	aLink := filepath.Join(mountDir, "a.txt")
	require.NoError(t, os.Symlink(bLink, aLink))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	exitCode, err := env.run([]string{"cat", aLink})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var aFound, bFound, targetFound bool
	for _, entry := range env.logger.Entries() {
		switch {
		case entry.Target == aLink && entry.Operation == accesslog.OperationRead:
			aFound = true
			assert.Equal(t, accesslog.ResultOK, entry.Result)
		case entry.Target == bLink && entry.Operation == accesslog.OperationRead:
			bFound = true
			assert.Equal(t, accesslog.ResultOK, entry.Result)
		case entry.Target == targetFile && entry.Operation == accesslog.OperationRead:
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, entry.Result)
		}
	}
	assert.True(t, aFound)
	assert.True(t, bFound)
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_MultiHopChainBreaksAtDeniedIntermediateHop(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// hop1 (ruled) → hop2 (unruled) → target (ruled)
	ruledDir := filepath.Join(absTestDir, "ruled")
	unruledDir := filepath.Join(absTestDir, "unruled")
	require.NoError(t, os.MkdirAll(ruledDir, 0o750))
	require.NoError(t, os.MkdirAll(unruledDir, 0o750))
	targetFile := filepath.Join(ruledDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))

	// hop2 is in unruled dir — will be denied
	hop2 := filepath.Join(unruledDir, "hop2.txt")
	require.NoError(t, os.Symlink(targetFile, hop2))
	// hop1 is in ruled dir — will be allowed
	hop1 := filepath.Join(ruledDir, "hop1.txt")
	require.NoError(t, os.Symlink(hop2, hop1))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(ruledDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	_, err = env.run([]string{"sh", "-c", "cat " + hop1 + " || true"})
	require.NoError(t, err)

	// hop1 must be logged as READ OK
	var hop1Found bool
	for _, e := range env.logger.Entries() {
		if e.Target == hop1 && e.Operation == accesslog.OperationRead {
			hop1Found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, hop1Found)

	// hop2 must be logged as READ DENY (no matching rule)
	var hop2Found bool
	for _, e := range env.logger.Entries() {
		if e.Target == hop2 && e.Operation == accesslog.OperationRead {
			hop2Found = true
			assert.Equal(t, accesslog.ResultDeny, e.Result)
		}
	}
	assert.True(t, hop2Found)

	// Target must NOT be logged — chain broke at hop2
	for _, e := range env.logger.Entries() {
		assert.NotEqual(t, targetFile, e.Target)
	}
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_SymlinkInIntermediatePathComponentResolved(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a real directory with a file, and a directory symlink
	mountDir := filepath.Join(absTestDir, "mount")
	realSubDir := filepath.Join(mountDir, "realsub")
	require.NoError(t, os.MkdirAll(realSubDir, 0o750))
	targetFile := filepath.Join(realSubDir, "file.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))

	// dir symlink in the middle of the path
	linkSubDir := filepath.Join(mountDir, "linksub")
	require.NoError(t, os.Symlink(realSubDir, linkSubDir))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Access file through the directory symlink
	accessPath := filepath.Join(linkSubDir, "file.txt")
	exitCode, err := env.run([]string{"cat", accessPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The dir symlink hop must be logged as a READ
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkSubDir && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, hopFound)

	// The resolved target (through the real subdir) must be logged
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationRead {
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_WriteOperationThroughSymlinkWithinMount(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	targetFile := filepath.Join(mountDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("old"), 0o600))
	linkFile := filepath.Join(mountDir, "link.txt")
	require.NoError(t, os.Symlink(targetFile, linkFile))

	// rw rule — both hop READ and target WRITE are allowed
	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{rwRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "echo new > " + linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The hop must be logged as READ OK
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, hopFound)

	// The target must be logged as WRITE OK
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationWrite {
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_WriteThroughSymlinkToReadOnlyTargetDenied(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Symlink in rw dir → file in ro dir
	rwDir := filepath.Join(absTestDir, "rwdir")
	roDir := filepath.Join(absTestDir, "rodir")
	require.NoError(t, os.MkdirAll(rwDir, 0o750))
	require.NoError(t, os.MkdirAll(roDir, 0o750))
	targetFile := filepath.Join(roDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("old"), 0o600))
	linkFile := filepath.Join(rwDir, "link.txt")
	require.NoError(t, os.Symlink(targetFile, linkFile))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{rwRule(rwDir), roRule(roDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	_, err = env.run([]string{"sh", "-c", "echo new > " + linkFile + " || true"})
	require.NoError(t, err)

	// The hop must be logged as READ OK (symlink in rw dir is readable)
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, hopFound)

	// The target must be logged as WRITE DENY (ro dir doesn't allow writes)
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationWrite {
			targetFound = true
			assert.Equal(t, accesslog.ResultDeny, e.Result)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_WriteThroughReadOnlySymlinkToWritableTargetAllowed(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Symlink in ro dir → file in rw dir
	roDir := filepath.Join(absTestDir, "rodir")
	rwDir := filepath.Join(absTestDir, "rwdir")
	require.NoError(t, os.MkdirAll(roDir, 0o750))
	require.NoError(t, os.MkdirAll(rwDir, 0o750))
	targetFile := filepath.Join(rwDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("old"), 0o600))
	linkFile := filepath.Join(roDir, "link.txt")
	require.NoError(t, os.Symlink(targetFile, linkFile))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(roDir), rwRule(rwDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "echo new > " + linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// The hop must be logged as READ OK (symlink in ro dir is readable)
	var hopFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == linkFile && e.Operation == accesslog.OperationRead {
			hopFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, hopFound)

	// The target must be logged as WRITE OK (rw dir allows writes)
	var targetFound bool
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationWrite {
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, targetFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_SymlinkDepthLimitExceeded(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Create a circular symlink pair: loop-a → loop-b → loop-a
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	loopA := filepath.Join(mountDir, "loop-a")
	loopB := filepath.Join(mountDir, "loop-b")
	require.NoError(t, os.Symlink(loopB, loopA))
	require.NoError(t, os.Symlink(loopA, loopB))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// The sleep keeps the process alive so strace can flush all output to the
	// pipe before the traced process exits. Without it, cat's ELOOP causes an
	// immediate exit and a strace pipe read race.
	_, err = env.run([]string{"sh", "-c", "cat " + loopA + " 2>/dev/null || true; sleep 0.5"})
	require.NoError(t, err)

	// There must be an entry with the depth-limit-exceeded rule
	var depthLimitFound bool
	for _, e := range env.logger.Entries() {
		if e.Rule == accesslog.RuleSymlinkDepthExceeded {
			depthLimitFound = true
			assert.Equal(t, accesslog.ResultDeny, e.Result)
		}
	}
	assert.True(t, depthLimitFound)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_ResolvedSymlinkPathsDeduplicated(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Two symlinks pointing to the same target
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	targetFile := filepath.Join(mountDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0o600))
	link1 := filepath.Join(mountDir, "link1.txt")
	link2 := filepath.Join(mountDir, "link2.txt")
	require.NoError(t, os.Symlink(targetFile, link1))
	require.NoError(t, os.Symlink(targetFile, link2))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Read through both symlinks — both resolve to the same target
	exitCode, err := env.run([]string{"sh", "-c", "cat " + link1 + " && cat " + link2})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// Count how many times the target path appears as a READ entry.
	// Logger deduplication should filter the second READ for the same target.
	targetReadCount := 0
	for _, e := range env.logger.Entries() {
		if e.Target == targetFile && e.Operation == accesslog.OperationRead {
			targetReadCount++
		}
	}
	assert.Equal(t, 1, targetReadCount)
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_NonExistentPathNotResolved(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	noexistFile := filepath.Join(mountDir, "noexist.txt")

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Read of a non-existent path — resolver sees ENOENT, sets pathNotFound,
	// and the monitor filters the read (noise reduction).
	_, err = env.run([]string{"sh", "-c", "cat " + noexistFile + " || true"})
	require.NoError(t, err)

	for _, e := range env.logger.Entries() {
		assert.NotEqual(t, noexistFile, e.Target)
	}
}

func TestIntegration_SymlinkPathResolutionInAccessLogging_SymlinkThroughManagedPathLoggedAsUnknown(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	mountDir := filepath.Join(absTestDir, "mount")
	managedDir := filepath.Join(absTestDir, "managed")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.MkdirAll(managedDir, 0o750))

	// Symlink in ruled dir points to a managed path
	managedFile := filepath.Join(managedDir, "file.txt")
	require.NoError(t, os.WriteFile(managedFile, []byte("managed"), 0o600))
	linkFile := filepath.Join(mountDir, "link.txt")
	require.NoError(t, os.Symlink(managedFile, linkFile))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      []string{managedDir},
			InterpreterPath:   "",
		}
	})

	_, err = env.run([]string{"sh", "-c", "cat " + linkFile + " || true"})
	require.NoError(t, err)

	// The entry must be logged as UNKNOWN with the unresolvable rule
	var found bool
	for _, e := range env.logger.Entries() {
		if e.Rule == accesslog.RuleSymlinkTargetUnresolvable {
			found = true
			assert.Equal(t, accesslog.ResultUnknown, e.Result)
		}
	}
	assert.True(t, found)
}

// --- Requirement: Non-existent path filtering for reads ---

func TestIntegration_NonExistentPathFilteringForReads_NonExistentReadFilteredFromLog(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	noexistFile := filepath.Join(mountDir, "noexist.txt")

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// cat fails because the file does not exist
	_, err = env.run([]string{"sh", "-c", "cat " + noexistFile + " || true"})
	require.NoError(t, err)

	for _, e := range env.logger.Entries() {
		assert.NotEqual(t, noexistFile, e.Target, "non-existent read must not be logged")
	}
}

func TestIntegration_NonExistentPathFilteringForReads_NonExistentWriteLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	newFile := filepath.Join(mountDir, "newfile.txt")

	// ro rule — monitor resolves this write as DENY
	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(mountDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Attempt to write a new (non-existent) file; the command may succeed at the
	// OS level (no bwrap enforcement in integration tests) but the monitor must log it.
	_, err = env.run([]string{"sh", "-c", "echo hello > " + newFile + " || true"})
	require.NoError(t, err)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == newFile && e.Operation == accesslog.OperationWrite {
			found = true
			assert.Equal(t, accesslog.ResultDeny, e.Result)
		}
	}
	assert.True(t, found, "write to non-existent path must be logged")
}

func TestIntegration_NonExistentPathFilteringForReads_StatErrorOtherThanEnoentStillLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	restrictedDir := filepath.Join(absTestDir, "restricted")
	secretFile := filepath.Join(restrictedDir, "secret.txt")

	require.NoError(t, os.MkdirAll(restrictedDir, 0o750))
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))

	// Mode 000 on the directory makes os.Lstat of the file inside return EACCES.
	require.NoError(t, os.Chmod(restrictedDir, 0o000))

	// Restore permissions before removal so t.Cleanup can delete the tree.
	t.Cleanup(func() {
		_ = os.Chmod(restrictedDir, 0o750) //nolint:gosec // Restore permissions for cleanup
		_ = os.RemoveAll(testDir)
	})

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// The command fails with EACCES; the monitor's lstat also returns EACCES (not ENOENT).
	// Fail-safe: when in doubt, log it.
	_, err = env.run([]string{"sh", "-c", "cat " + secretFile + " || true"})
	require.NoError(t, err)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == secretFile {
			found = true
		}
	}
	assert.True(t, found, "stat EACCES must be treated as fail-safe and logged")
}

func TestIntegration_RealTimeAccessLogWriting_LogEntriesAppearInSyscallOrder(t *testing.T) {
	// Use a directory outside /tmp to avoid managed path filtering
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	aFile := filepath.Join(absTestDir, "a.txt")
	bFile := filepath.Join(absTestDir, "b.txt")
	require.NoError(t, os.WriteFile(aFile, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(bFile, []byte("b"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{rwRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// Read a.txt then write b.txt
	exitCode, err := env.run([]string{"sh", "-c", "cat " + aFile + " && echo new > " + bFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	lines := strings.Split(logStr, "\n")

	readIdx := -1
	writeIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "READ") && strings.Contains(line, "a.txt") {
			readIdx = i
		}
		if strings.Contains(line, "WRITE") && strings.Contains(line, "b.txt") {
			writeIdx = i
		}
	}

	require.NotEqual(t, -1, readIdx)
	require.NotEqual(t, -1, writeIdx)
	assert.Less(t, readIdx, writeIdx)
}

// --- Requirement: Path resolution for *at() syscalls ---

// skipIfNoGccOrNotAMD64 skips the test if gcc is unavailable or the architecture
// is not amd64. Tests that require static binaries with x86_64 inline assembly
// must call this.
func skipIfNoGccOrNotAMD64(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("test requires amd64 (got %s)", runtime.GOARCH)
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}
}

// skipIfNoGcc skips the test if gcc is unavailable.
func skipIfNoGcc(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}
}

// compileStaticBinary compiles a minimal x86_64 static binary (no libc/dynamic linker)
// from the given C source. The binary is written to binPath.
// Tests must call skipIfNoGccOrNotAMD64 before using this helper.
func compileStaticBinary(t *testing.T, src, binPath string) {
	t.Helper()
	cmd := exec.Command("gcc", "-nostdlib", "-static", "-o", binPath, src)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "gcc failed: %s", out)
}

// compileBinary compiles a standard C binary (with libc/dynamic linker)
// from the given C source. The binary is written to binPath.
func compileBinary(t *testing.T, src, binPath string) {
	t.Helper()
	cmd := exec.Command("gcc", "-o", binPath, src)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "gcc failed: %s", out)
}

// testDirWithFile creates a temporary directory outside /tmp containing a single file.
// Returns the absolute directory path and the absolute file path.
func testDirWithFile(t *testing.T, fileName, content string) (string, string) {
	t.Helper()
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	absFilePath := filepath.Join(absTestDir, fileName)
	require.NoError(t, os.WriteFile(absFilePath, []byte(content), 0o600))
	return absTestDir, absFilePath
}

// roRuleEnv creates a monitor test env with a single read-only rule for the given directory.
func roRuleEnv(t *testing.T, absTestDir string) *monitorTestEnv {
	t.Helper()
	return newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})
}

// assertHasReadEntry asserts that the logger contains a READ entry with ResultOK for the given target.
func assertHasReadEntry(t *testing.T, entries []accesslog.Entry, target string) {
	t.Helper()
	var found bool
	for _, e := range entries {
		if e.Target == target && e.Operation == accesslog.OperationRead {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, found)
}

// TestIntegration_PathResolutionForAtSyscalls_AbsoluteDirfdIgnored tests that when an
// *at() syscall is called with an absolute path, the dirfd is not used for path
// resolution. The logged path is exactly the absolute path argument.
func TestIntegration_PathResolutionForAtSyscalls_AbsoluteDirfdIgnored(t *testing.T) {
	absTestDir, testFile := testDirWithFile(t, "file.txt", "content")
	env := roRuleEnv(t, absTestDir)

	// cat calls openat(AT_FDCWD<working_dir>, "/absolute/path", O_RDONLY).
	// Since the path is absolute, the AT_FDCWD annotation is ignored.
	exitCode, err := env.run([]string{"cat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assertHasReadEntry(t, env.logger.Entries(), testFile)
}

// TestIntegration_PathResolutionForAtSyscalls_AtFdCwdResolvesWithTrackedCwd tests that
// when strace annotates AT_FDCWD with a directory path, a relative path argument is
// joined with that annotation to produce an absolute logged path.
func TestIntegration_PathResolutionForAtSyscalls_AtFdCwdResolvesWithTrackedCwd(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	subDir := filepath.Join(absTestDir, "sub")
	require.NoError(t, os.MkdirAll(subDir, 0o750))
	testFile := filepath.Join(subDir, "file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:           []fsrules.AccessRule{roRule(absTestDir)},
			NetRules:          nil,
			FSLogRules:        nil,
			NetLogRules:       nil,
			SyscallAllowRules: nil,
			SyscallNologRules: nil,
			ManagedPaths:      nil,
			InterpreterPath:   "",
		}
	})

	// sh changes cwd to subDir; cat then runs with cwd=subDir.
	// strace -y annotates: openat(AT_FDCWD<subDir>, "file.txt", O_RDONLY)
	// parseLine joins annotation + "file.txt" → subDir/file.txt
	exitCode, err := env.run([]string{"sh", "-c", "cd " + subDir + " && cat file.txt"})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, found, "AT_FDCWD annotation must be joined with relative path to form absolute path")
}

// TestIntegration_PathResolutionForAtSyscalls_AtFdCwdUnresolvableWhenNoCwdTracked tests
// that when strace cannot annotate AT_FDCWD and no cwd has been tracked for the pid,
// a relative path is logged as UNKNOWN. Uses a minimal static binary to ensure the
// access syscall is the first traceable call, before any cwd-establishing annotation.
func TestIntegration_PathResolutionForAtSyscalls_AtFdCwdUnresolvableWhenNoCwdTracked(t *testing.T) {
	skipIfNoGccOrNotAMD64(t)

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "bare_access.c")
	binFile := filepath.Join(tmpDir, "bare_access")

	// Minimal static binary: calls access("untracked/relative.txt") directly via
	// x86_64 inline assembly. No dynamic linker means no AT_FDCWD annotation
	// precedes the access call, so no cwd is tracked for this pid.
	require.NoError(t, os.WriteFile(srcFile, []byte(`
long sys_access(const char *path, int mode) {
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "0"(21), "D"(path), "S"(mode) : "rcx", "r11", "memory");
	return ret;
}
void sys_exit(int code) {
	__asm__ volatile("syscall" :: "a"(231), "D"(code));
	__builtin_unreachable();
}
void _start(void) {
	sys_access("untracked/relative.txt", 0);
	sys_exit(0);
}
`), 0o600))
	compileStaticBinary(t, srcFile, binFile)

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return new(config.Config)
	})

	exitCode, err := env.run([]string{binFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == "untracked/relative.txt" {
			found = true
			assert.Equal(t, accesslog.ResultUnknown, e.Result)
			assert.Equal(t, accesslog.RuleUnresolvedRelativePath, e.Rule)
		}
	}
	assert.True(t, found, "relative path without tracked cwd must be logged as UNKNOWN")
}

// TestIntegration_PathResolutionForAtSyscalls_RelativeDirfdResolvesWithTrackedCwd tests
// that when strace annotates a numeric dirfd with a directory path, a relative path
// argument is joined with that fd annotation to produce an absolute logged path.
func TestIntegration_PathResolutionForAtSyscalls_RelativeDirfdResolvesWithTrackedCwd(t *testing.T) {
	skipIfNoGcc(t)

	absTestDir, testFile := testDirWithFile(t, "file.txt", "data")

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "dirfd_open.c")
	binFile := filepath.Join(tmpDir, "dirfd_open")
	require.NoError(t, os.WriteFile(srcFile, []byte(`
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
	int dirfd = open(argv[1], O_RDONLY|O_DIRECTORY);
	if (dirfd < 0) return 1;
	int fd = openat(dirfd, "file.txt", O_RDONLY);
	if (fd >= 0) close(fd);
	close(dirfd);
	return 0;
}
`), 0o600))
	compileBinary(t, srcFile, binFile)

	env := roRuleEnv(t, absTestDir)

	// The C program calls openat(dirfd, "file.txt", O_RDONLY).
	// strace -y annotates: openat(3<absTestDir>, "file.txt", O_RDONLY)
	// parseLine joins: absTestDir/file.txt
	exitCode, err := env.run([]string{binFile, absTestDir})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assertHasReadEntry(t, env.logger.Entries(), testFile)
}

// TestIntegration_PathResolutionForAtSyscalls_RelativeDirfdUnresolvableWhenNoCwdTracked
// tests that when a numeric dirfd has no path annotation (strace could not resolve it)
// and no cwd is tracked for the pid, a relative path is logged as UNKNOWN.
// Uses a static binary to avoid cwd-establishing calls from the dynamic linker.
func TestIntegration_PathResolutionForAtSyscalls_RelativeDirfdUnresolvableWhenNoCwdTracked(t *testing.T) {
	skipIfNoGccOrNotAMD64(t)

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "fd_relative.c")
	binFile := filepath.Join(tmpDir, "fd_relative")

	// Minimal static binary: calls openat(42, "fd-relative.txt", O_RDONLY) via inline
	// assembly. fd 42 does not exist, so strace cannot annotate it. Combined with no
	// dynamic linker (no AT_FDCWD annotation), no cwd is tracked → UNKNOWN.
	require.NoError(t, os.WriteFile(srcFile, []byte(`
long sys_openat(int dirfd, const char *path, int flags) {
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "0"(257), "D"(dirfd), "S"(path), "d"(flags) : "rcx", "r11", "memory");
	return ret;
}
void sys_exit(int code) {
	__asm__ volatile("syscall" :: "a"(231), "D"(code));
	__builtin_unreachable();
}
void _start(void) {
	sys_openat(42, "fd-relative.txt", 0); /* EBADF – fd 42 does not exist */
	sys_exit(0);
}
`), 0o600))
	compileStaticBinary(t, srcFile, binFile)

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return new(config.Config)
	})

	exitCode, err := env.run([]string{binFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if strings.HasSuffix(e.Target, "fd-relative.txt") {
			found = true
			assert.Equal(t, accesslog.ResultUnknown, e.Result)
			assert.Equal(t, accesslog.RuleUnresolvedRelativePath, e.Rule)
		}
	}
	assert.True(t, found, "unannotated numeric dirfd with relative path and no tracked cwd must be UNKNOWN")
}

// TestIntegration_PathResolutionForAtSyscalls_EmptyPathWithAtEmptyPath tests that when
// an *at() syscall uses an empty path argument with a numeric dirfd annotated by strace
// (AT_EMPTY_PATH usage), the fd's annotated path is logged as the accessed path.
func TestIntegration_PathResolutionForAtSyscalls_EmptyPathWithAtEmptyPath(t *testing.T) {
	skipIfNoGcc(t)

	absTestDir, testFile := testDirWithFile(t, "statme.txt", "data")

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "at_empty_path.c")
	binFile := filepath.Join(tmpDir, "at_empty_path")
	// The program opens a file and calls fstatat(fd, "", AT_EMPTY_PATH).
	// Strace -y shows: newfstatat(3</path/to/statme.txt>, "", AT_EMPTY_PATH|...)
	// The monitor must use the fd's annotated path as the accessed path.
	require.NoError(t, os.WriteFile(srcFile, []byte(`
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) return 1;
	struct stat st;
	fstatat(fd, "", &st, AT_EMPTY_PATH);
	close(fd);
	return 0;
}
`), 0o600))
	compileBinary(t, srcFile, binFile)

	env := roRuleEnv(t, absTestDir)

	exitCode, err := env.run([]string{binFile, testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assertHasReadEntry(t, env.logger.Entries(), testFile)
}

// TestIntegration_PathResolutionForAtSyscalls_ChdirUpdatesCwdForPid tests that a
// successful chdir() call updates the monitored pid's tracked cwd, so subsequent
// bare-path syscalls from that pid resolve against the new cwd.
func TestIntegration_PathResolutionForAtSyscalls_ChdirUpdatesCwdForPid(t *testing.T) {
	skipIfNoGcc(t)

	absTestDir, testFile := testDirWithFile(t, "file.txt", "data")

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "chdir_access.c")
	binFile := filepath.Join(tmpDir, "chdir_access")
	// The program calls chdir(dir) then access("file.txt").
	// chdir updates cwdByPid; the subsequent bare-path access("file.txt")
	// resolves to dir/file.txt.
	require.NoError(t, os.WriteFile(srcFile, []byte(`
#include <unistd.h>
int main(int argc, char *argv[]) {
	chdir(argv[1]);
	access("file.txt", R_OK);
	return 0;
}
`), 0o600))
	compileBinary(t, srcFile, binFile)

	env := roRuleEnv(t, absTestDir)

	exitCode, err := env.run([]string{binFile, absTestDir})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assertHasReadEntry(t, env.logger.Entries(), testFile)
}

// TestIntegration_PathResolutionForAtSyscalls_FchdirUpdatesCwdForPid tests that a
// successful fchdir() call updates the monitored pid's tracked cwd to the fd's
// annotated path, so subsequent bare-path syscalls resolve against the new cwd.
func TestIntegration_PathResolutionForAtSyscalls_FchdirUpdatesCwdForPid(t *testing.T) {
	skipIfNoGcc(t)

	absTestDir, testFile := testDirWithFile(t, "file.txt", "data")

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "fchdir_access.c")
	binFile := filepath.Join(tmpDir, "fchdir_access")
	// The program opens a directory fd, calls fchdir(fd), then access("file.txt").
	// fchdir updates cwdByPid to fd's annotated path; bare-path access resolves.
	require.NoError(t, os.WriteFile(srcFile, []byte(`
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
	int dirfd = open(argv[1], O_RDONLY|O_DIRECTORY);
	if (dirfd < 0) return 1;
	fchdir(dirfd);
	access("file.txt", R_OK);
	close(dirfd);
	return 0;
}
`), 0o600))
	compileBinary(t, srcFile, binFile)

	env := roRuleEnv(t, absTestDir)

	exitCode, err := env.run([]string{binFile, absTestDir})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assertHasReadEntry(t, env.logger.Entries(), testFile)
}

// TestIntegration_PathResolutionForAtSyscalls_CwdClearedOnProcessExit tests that
// cwd tracking state does not persist across monitor runs. Each call to mon.Run()
// starts with a fresh cwdByPid, so no pid's cwd from a previous run can influence
// path resolution in a subsequent run.
func TestIntegration_PathResolutionForAtSyscalls_CwdClearedOnProcessExit(t *testing.T) {
	skipIfNoGccOrNotAMD64(t)

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "bare_access2.c")
	binFile := filepath.Join(tmpDir, "bare_access2")
	require.NoError(t, os.WriteFile(srcFile, []byte(`
long sys_access(const char *path, int mode) {
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "0"(21), "D"(path), "S"(mode) : "rcx", "r11", "memory");
	return ret;
}
void sys_exit(int code) {
	__asm__ volatile("syscall" :: "a"(231), "D"(code));
	__builtin_unreachable();
}
void _start(void) {
	sys_access("post-exit/relative.txt", 0);
	sys_exit(0);
}
`), 0o600))
	compileStaticBinary(t, srcFile, binFile)

	// Run 1: a normal command that establishes cwd tracking for its pids.
	env1 := newMonitorTestEnv(t, func(_ string) *config.Config {
		return new(config.Config)
	})
	_, _ = env1.run([]string{"sh", "-c", "true"})

	// Run 2: fresh env — cwdByPid from run 1 is gone. Static binary makes a
	// bare-path access with no dynamic linker, so no cwd is established.
	// The path must be UNKNOWN regardless of what run 1 tracked.
	env2 := newMonitorTestEnv(t, func(_ string) *config.Config {
		return new(config.Config)
	})
	exitCode, err := env2.run([]string{binFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env2.logger.Entries() {
		if e.Target == "post-exit/relative.txt" {
			found = true
			assert.Equal(t, accesslog.ResultUnknown, e.Result)
			assert.Equal(t, accesslog.RuleUnresolvedRelativePath, e.Rule)
		}
	}
	assert.True(t, found, "cwd state must not persist across monitor runs")
}

// TestIntegration_PathResolutionForAtSyscalls_CwdNotInheritedByNewPid tests that a
// new process (created via fork from a parent that has a tracked cwd) starts with
// no tracked cwd of its own. Its bare-path syscalls are UNKNOWN until it establishes
// its own cwd via AT_FDCWD annotation, chdir, or fchdir.
func TestIntegration_PathResolutionForAtSyscalls_CwdNotInheritedByNewPid(t *testing.T) {
	skipIfNoGccOrNotAMD64(t)

	tmpDir := t.TempDir()

	// Minimal static binary: its first syscall is access("child-relative.txt"),
	// before any AT_FDCWD-establishing call (no dynamic linker).
	childSrc := filepath.Join(tmpDir, "child_bare.c")
	childBin := filepath.Join(tmpDir, "child_bare")
	require.NoError(t, os.WriteFile(childSrc, []byte(`
long sys_access(const char *path, int mode) {
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "0"(21), "D"(path), "S"(mode) : "rcx", "r11", "memory");
	return ret;
}
void sys_exit(int code) {
	__asm__ volatile("syscall" :: "a"(231), "D"(code));
	__builtin_unreachable();
}
void _start(void) {
	sys_access("child-relative.txt", 0);
	sys_exit(0);
}
`), 0o600))
	compileStaticBinary(t, childSrc, childBin)

	// Dynamic wrapper: establishes cwd tracking for its own pid (via dynamic
	// linker AT_FDCWD annotations), then fork+execs the static child. The child
	// gets a new pid with no tracked cwd, so its access must be UNKNOWN.
	wrapperSrc := filepath.Join(tmpDir, "fork_exec.c")
	wrapperBin := filepath.Join(tmpDir, "fork_exec")
	require.NoError(t, os.WriteFile(wrapperSrc, []byte(`
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char *argv[]) {
	pid_t child = fork();
	if (child == 0) {
		char *args[] = {argv[1], (char *)0};
		execv(argv[1], args);
		_exit(1);
	}
	int status;
	waitpid(child, &status, 0);
	return 0;
}
`), 0o600))
	compileBinary(t, wrapperSrc, wrapperBin)

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return new(config.Config)
	})

	// The wrapper (dynamic) gets cwd tracked via AT_FDCWD annotations.
	// The child (forked, new pid, static) has no tracked cwd of its own.
	// The child's access("child-relative.txt") must be UNKNOWN.
	exitCode, err := env.run([]string{wrapperBin, childBin})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == "child-relative.txt" {
			found = true
			assert.Equal(t, accesslog.ResultUnknown, e.Result)
			assert.Equal(t, accesslog.RuleUnresolvedRelativePath, e.Rule)
		}
	}
	assert.True(t, found, "new pid must not inherit parent's tracked cwd")
}

// --- Requirement: Blocked syscall attempts produce SYSCALL entries ---

// TestIntegration_SyscallTracing_BlockedSyscallAttemptProducesSyscallEntry tests that when
// blockedSyscalls is set, a real strace run that intercepts a blocked syscall attempt
// produces a SYSCALL entry with DENY result and seccomp rule.
func TestIntegration_SyscallTracing_BlockedSyscallAttemptProducesSyscallEntry(t *testing.T) {
	_, err := exec.LookPath("python3")
	require.NoError(t, err)

	if runtime.GOARCH != "amd64" {
		t.Skip("bpf syscall number 321 is x86_64-specific")
	}

	cfg := &config.Config{
		FSRules:           []fsrules.AccessRule{roRule("/usr"), roRule("/lib"), roRule("/lib64"), roRule("/etc/ld.so.cache")},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
		InterpreterPath:   "",
	}
	logger := accesslog.New(cfg.ManagedPaths)
	resolver := fsrules.NewAccessResolver(cfg.FSRules, cfg.ManagedPaths)

	stracePath, err := sandbox.ResolveStrace()
	require.NoError(t, err)

	blocked := map[string]bool{"bpf": true}
	seccompFile, err := seccomp.FilterPipe(nil)
	require.NoError(t, err)
	mon := monitor.New("", stracePath, logger, resolver, nil, false, seccompFile, blocked, nil)

	// Python invokes the bpf syscall (nr 321 on x86_64) which is in our blocked set.
	// Without bwrap the seccomp filter is not applied, but strace still emits the
	// syscall. The monitor intercepts it based on the name and logs it as DENY.
	exitCode, err := mon.Run(context.Background(), []string{
		"python3", "-c", "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)",
	})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range logger.Entries() {
		if e.Operation == accesslog.OperationSyscall && e.Target == "bpf" {
			found = true
			assert.Equal(t, accesslog.ResultDeny, e.Result)
			assert.Equal(t, accesslog.RuleNoMatch, e.Rule)
		}
	}
	assert.True(t, found)
}

// TestIntegration_SyscallTracing_AllowedSyscallProducesSyscallOKEntry tests that when
// allowedSyscalls is set, a real strace run that intercepts an allowed syscall produces
// a SYSCALL entry with OK result.
func TestIntegration_SyscallTracing_AllowedSyscallProducesSyscallOKEntry(t *testing.T) {
	_, err := exec.LookPath("python3")
	require.NoError(t, err)

	if runtime.GOARCH != "amd64" {
		t.Skip("bpf syscall number 321 is x86_64-specific")
	}

	cfg := &config.Config{
		FSRules:           []fsrules.AccessRule{roRule("/usr"), roRule("/lib"), roRule("/lib64"), roRule("/etc/ld.so.cache")},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
		InterpreterPath:   "",
	}
	logger := accesslog.New(cfg.ManagedPaths)
	resolver := fsrules.NewAccessResolver(cfg.FSRules, cfg.ManagedPaths)

	stracePath, err := sandbox.ResolveStrace()
	require.NoError(t, err)

	// blockedSyscalls must be non-nil to enable syscall tracing in buildStraceArgs.
	// In production, both maps are populated from config when seccomp is active.
	blocked := map[string]bool{}
	allowed := map[string]bool{"bpf": true}
	seccompFile, err := seccomp.FilterPipe(allowed)
	require.NoError(t, err)
	mon := monitor.New("", stracePath, logger, resolver, nil, false, seccompFile, blocked, allowed)

	exitCode, err := mon.Run(context.Background(), []string{
		"python3", "-c", "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)",
	})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range logger.Entries() {
		if e.Operation == accesslog.OperationSyscall && e.Target == "bpf" {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "syscall:allow:bpf", e.Rule)
		}
	}
	assert.True(t, found)
}

// --- Requirement: Bwrap setup phase detection ---

func TestIntegration_BwrapSetupPhaseDetection_SetupPhaseLinesSkippedUntilUserCommandExecve(t *testing.T) {
	bwrapPath, err := sandbox.ResolveBwrap()
	if err != nil {
		t.Skip("bwrap not available: ", err)
	}
	stracePath, err := sandbox.ResolveStrace()
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
		FSRules: []fsrules.AccessRule{
			roRule("/usr"), roRule("/lib"), roRule("/lib64"), roRule("/etc/ld.so.cache"),
			roRule(absTestDir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
		InterpreterPath:   "",
	}
	logger := accesslog.New(cfg.ManagedPaths)
	resolver := fsrules.NewAccessResolver(cfg.FSRules, cfg.ManagedPaths)

	sb := sandbox.New(cfg, "", nil)
	bwrapArgs := sb.BuildBwrapArgs([]string{"cat", testFile})

	mon := monitor.New(bwrapPath, stracePath, logger, resolver, bwrapArgs, false, nil, nil, nil)

	exitCode, err := mon.Run(context.Background(), []string{"cat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	entries := logger.Entries()
	assert.NotEmpty(t, entries)

	// Bwrap setup operations must not appear in log
	for _, e := range entries {
		assert.NotContains(t, e.Target, "newroot")
		assert.NotContains(t, e.Target, "oldroot")
	}

	// User command's file access must appear
	var foundTestFile bool
	for _, e := range entries {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			foundTestFile = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, foundTestFile)
}

func TestIntegration_BwrapSetupPhaseDetection_IncompleteExecveChainStillProducesEntries(t *testing.T) {
	bwrapPath, err := sandbox.ResolveBwrap()
	if err != nil {
		t.Skip("bwrap not available: ", err)
	}
	stracePath, err := sandbox.ResolveStrace()
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
		FSRules: []fsrules.AccessRule{
			roRule("/usr"), roRule("/lib"), roRule("/lib64"), roRule("/etc/ld.so.cache"),
			roRule(absTestDir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
		InterpreterPath:   "",
	}
	logger := accesslog.New(cfg.ManagedPaths)
	resolver := fsrules.NewAccessResolver(cfg.FSRules, cfg.ManagedPaths)

	sb := sandbox.New(cfg, "", nil)
	bwrapArgs := sb.BuildBwrapArgs([]string{"cat", testFile})

	// hasNetworkPath=true expects 3 execves, but no tunnel is configured
	// in bwrapArgs, so only 2 execves occur (bwrap + user command).
	// The monitor must still produce entries despite the incomplete chain.
	mon := monitor.New(bwrapPath, stracePath, logger, resolver, bwrapArgs, true, nil, nil, nil)

	exitCode, err := mon.Run(context.Background(), []string{"cat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	entries := logger.Entries()
	assert.NotEmpty(t, entries)

	// User command's file access must still appear despite incomplete execve chain
	var foundTestFile bool
	for _, e := range entries {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			foundTestFile = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, foundTestFile)
}
