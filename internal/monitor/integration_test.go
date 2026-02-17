package monitor_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
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
			FSRules:      []fsrules.Rule{roRule(dataDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// cat triggers openat(O_RDONLY) — classified as READ by classifyOpenOperation.
	exitCode, err := env.run([]string{"cat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var found bool
	for _, e := range env.logger.Entries() {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			found = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		}
	}
	assert.True(t, found, "openat(O_RDONLY) must be classified as READ")
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
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(linkDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(linkDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", aLink})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// Both hops must be logged as READ
	var aFound, bFound, targetFound bool
	for _, e := range env.logger.Entries() {
		switch {
		case e.Target == aLink && e.Operation == accesslog.OperationRead:
			aFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		case e.Target == bLink && e.Operation == accesslog.OperationRead:
			bFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		case e.Target == targetFile && e.Operation == accesslog.OperationRead:
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", aLink})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	var aFound, bFound, targetFound bool
	for _, e := range env.logger.Entries() {
		switch {
		case e.Target == aLink && e.Operation == accesslog.OperationRead:
			aFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		case e.Target == bLink && e.Operation == accesslog.OperationRead:
			bFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
		case e.Target == targetFile && e.Operation == accesslog.OperationRead:
			targetFound = true
			assert.Equal(t, accesslog.ResultOK, e.Result)
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
			FSRules:      []fsrules.Rule{roRule(ruledDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{rwRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{rwRule(rwDir), roRule(roDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(roDir), rwRule(rwDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: []string{managedDir},
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
		_ = os.Chmod(restrictedDir, 0o750)
		_ = os.RemoveAll(testDir)
	})

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
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
