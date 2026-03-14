package e2e_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SandboxingFilesystem_RunCommandWithReadOnlySystemAccess(t *testing.T) {
	// fs:ro grants read access but blocks all writes (overwrite and create) to the path.
	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.file("data.txt", "hello from sandbox")

	s.givenRules("fs:ro:" + data.String())

	// Reading an existing file succeeds.
	s.whenRun("cat", testFile)
	s.thenExitCode(0)
	s.thenStdoutContains("hello from sandbox")

	// Writing to an existing file is denied.
	s.whenRun("sh", "-c", "echo x > "+testFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("Read-only file system")

	// Creating a new file is also denied.
	s.whenRun("touch", data.join("new.txt"))
	s.thenExitCodeNonZero()
	s.thenStderrContains("Read-only file system")
}

func Test_SandboxingFilesystem_RunCommandWithReadWriteProjectAccess(t *testing.T) {
	// fs:rw grants full read and write access: creating new files, overwriting existing
	// files, and reading files all succeed within the granted directory.
	s := newScenario(t)
	data := s.givenDir("data")
	existingFile := data.file("existing.txt", "old content")
	newFile := data.join("output.txt")

	s.givenRules("fs:rw:" + data.String())

	// Creating a new file succeeds.
	s.whenRun("sh", "-c", "echo 'written' > "+newFile)
	s.thenExitCode(0)
	s.thenFileContains(newFile, "written")

	// Overwriting an existing file succeeds.
	s.whenRun("sh", "-c", "echo 'new content' > "+existingFile)
	s.thenExitCode(0)
	s.thenFileContains(existingFile, "new content")

	// Reading a file succeeds.
	s.whenRun("cat", newFile)
	s.thenExitCode(0)
	s.thenStdoutContains("written")
}

func Test_SandboxingFilesystem_ProtectSensitiveFilesWithNoAccessRules(t *testing.T) {
	// fs:none carves a file out of an otherwise rw directory, blocking all access (read and write).
	s := newScenario(t)
	data := s.givenDir("data")
	envFile := data.file(".env", "SECRET=password")
	normalFile := data.file("data.txt", "normal data")

	s.givenRules("fs:rw:"+data.String(), "fs:none:"+envFile)

	// Reading the protected file is denied.
	s.whenRun("cat", envFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains(".env: Permission denied")

	// Writing to the protected file is also denied.
	s.whenRun("sh", "-c", "echo x >> "+envFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains(".env: Permission denied")

	// Reading other files in the parent rw area still works.
	s.whenRun("cat", normalFile)
	s.thenExitCode(0)
	s.thenStdoutContains("normal data")

	// Writing other files in the parent rw area still works.
	s.whenRun("sh", "-c", "echo new >> "+normalFile)
	s.thenExitCode(0)
}

func Test_SandboxingFilesystem_OverrideParentRuleWithMoreSpecificChildRule(t *testing.T) { //nolint:funlen // e2e scenario test
	// The most specific rule (longest path match) wins when rules overlap, regardless of direction.
	s := newScenario(t)

	// Scenario 1: child restricts parent (rw:parent + ro:child).
	proj := s.givenDir("proj")
	gitDir := proj.join(".git")
	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)
	gitFile := proj.file(".git/config", "existing")
	srcFile := proj.file("src/main.go", "package main")

	s.givenRules("fs:rw:"+proj.String(), "fs:ro:"+gitDir)

	// Writing to .git is denied (ro child overrides rw parent).
	s.whenRun("sh", "-c", "echo test > "+gitFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("config: Read-only file system")

	// Reading from .git succeeds.
	s.whenRun("cat", gitFile)
	s.thenExitCode(0)
	s.thenStdoutContains("existing")

	// Writing outside the child dir succeeds (parent rw rule applies).
	s.whenRun("sh", "-c", "echo 'updated' > "+srcFile)
	s.thenExitCode(0)

	// Scenario 2: child upgrades parent (ro:parent + rw:child).
	area := s.givenDir("area")
	workDir := s.givenDir("area/work")
	workFile := workDir.join("output.txt")
	otherFile := area.file("other.txt", "other")

	s.givenRules("fs:ro:"+area.String(), "fs:rw:"+workDir.String())

	// Writing inside the rw child dir succeeds (child rw overrides parent ro).
	s.whenRun("sh", "-c", "echo written > "+workFile)
	s.thenExitCode(0)

	// Writing outside the child dir is denied (parent ro applies).
	s.whenRun("sh", "-c", "echo x > "+otherFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("Read-only file system")

	// Scenario 3: three nested rules (ro:grandparent + rw:parent + none:child).
	// Each level wins at its own depth.
	root := s.givenDir("root")
	mid := s.givenDir("root/mid")
	leaf := s.givenDir("root/mid/leaf")
	rootFile := root.file("top.txt", "top")
	midFile := mid.file("mid.txt", "mid")
	leafFile := leaf.file("leaf.txt", "leaf")

	s.givenRules("fs:ro:"+root.String(), "fs:rw:"+mid.String(), "fs:none:"+leaf.String())

	// root level: ro — read succeeds, write denied.
	s.whenRun("cat", rootFile)
	s.thenExitCode(0)
	s.thenStdoutContains("top")
	s.whenRun("sh", "-c", "echo x > "+rootFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("Read-only file system")

	// mid level: rw — read and write succeed.
	s.whenRun("cat", midFile)
	s.thenExitCode(0)
	s.whenRun("sh", "-c", "echo x > "+midFile)
	s.thenExitCode(0)

	// leaf level: none — all access denied.
	s.whenRun("cat", leafFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("Permission denied")
}

func Test_SandboxingFilesystem_AccessFilesThroughSymlinksWithAllowedTarget(t *testing.T) {
	// Symlink accesses are governed by the target's permission level: reads and writes
	// succeed or fail based on the target path's rule, not the symlink's rule.
	s := newScenario(t)
	project := s.givenDir("project")
	target := s.givenDir("target")
	targetFile := target.file("data.txt", "target content")
	linkFile := project.join("data-link")
	s.givenSymlink(targetFile, linkFile)

	// Reading through a symlink succeeds when both the symlink path and target are accessible.
	s.givenRules("fs:rw:"+project.String(), "fs:ro:"+target.String())
	s.whenRun("cat", linkFile)
	s.thenExitCode(0)
	s.thenStdoutContains("target content")

	// Writing through a symlink succeeds when the target is rw.
	s.givenRules("fs:rw:"+project.String(), "fs:rw:"+target.String())
	s.whenRun("sh", "-c", "echo 'new content' > "+linkFile)
	s.thenExitCode(0)
	s.thenFileContains(targetFile, "new content")

	// Writing through a symlink in an rw dir is denied when the target is ro — the target's
	// rule governs write access, not the symlink's rule.
	s.givenRules("fs:rw:"+project.String(), "fs:ro:"+target.String())
	s.whenRun("sh", "-c", "echo x > "+linkFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("Read-only file system")
}

func Test_SandboxingFilesystem_SymlinkToInaccessibleTargetDenied(t *testing.T) {
	// Symlinks pointing to paths not covered by any rule are denied: the target
	// is never mounted, so the symlink is dangling inside the sandbox.
	s := newScenario(t)
	secret := s.givenDir("secret")
	secret.file("data.txt", "secret data")
	public := s.givenDir("public")
	linkFile := public.join("link.txt")
	shadowLink := public.join("shadow-link")
	s.givenSymlink(secret.join("data.txt"), linkFile)
	s.givenSymlink("/etc/shadow", shadowLink)

	s.givenRules("fs:rw:" + public.String())

	cases := []struct {
		name string
		args []string
		link string
	}{
		{
			name: "read through symlink to unruled dir",
			args: []string{"cat", linkFile},
			link: "link.txt",
		},
		{
			name: "write through symlink to unruled dir",
			args: []string{"sh", "-c", "echo x > " + linkFile},
			link: "link.txt",
		},
		{
			name: "read through symlink to sensitive system path",
			args: []string{"cat", shadowLink},
			link: "shadow-link",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(_ *testing.T) {
			s.whenRun(tt.args...)
			s.thenExitCodeNonZero()
			s.thenStderrContains(tt.link + ": No such file or directory")
		})
	}
}

func Test_SandboxingFilesystem_DefaultDenyForUnmatchedPaths(t *testing.T) {
	// Paths not covered by any rule are inaccessible: the sandbox only mounts
	// explicitly allowed paths, so unmatched paths appear to not exist.
	s := newScenario(t)
	data := s.givenDir("data")
	tempFile := data.file("secret.txt", "secret data")

	s.givenRules()

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "read unruled temp file",
			args: []string{"cat", tempFile},
		},
		{
			name: "write to unruled temp path",
			args: []string{"sh", "-c", "echo x > " + data.join("new.txt")},
		},
		{
			name: "well-known system path not in rules",
			args: []string{"cat", "/etc/passwd"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(_ *testing.T) {
			s.whenRun(tt.args...)
			s.thenExitCodeNonZero()
			s.thenStderrContains("No such file or directory")
		})
	}
}

func Test_SandboxingFilesystem_RuleDoesNotMatchSiblingWithSharedPrefix(t *testing.T) {
	// A rule for /path/user must not grant access to /path/user2 — the match
	// must respect path-component boundaries, not just string prefixes.
	s := newScenario(t)
	user := s.givenDir("user")
	user.file("data.txt", "user data")
	user2 := s.givenDir("user2")
	user2file := user2.file("data.txt", "user2 data")

	// Only grant access to "user", not "user2".
	s.givenRules("fs:ro:" + user.String())

	s.whenRun("cat", user2file)
	s.thenExitCodeNonZero()
	s.thenStderrContains("No such file or directory")
}

func Test_SandboxingFilesystem_NoneDirectoryWithAccessibleChildPath(t *testing.T) {
	// A fs:none rule on a directory is overridden by a more specific fs:rw rule on a
	// child subdirectory: the child is accessible while the parent directory is blocked.
	s := newScenario(t)
	tmp := s.givenDir("tmp")
	parent := s.givenDir("tmp/parent")
	child := s.givenDir("tmp/parent/child")
	childFile := child.file("data.txt", "child content")
	parentFile := parent.file("direct.txt", "direct content")

	s.givenRules(
		"fs:rw:"+tmp.String(),
		"fs:none:"+parent.String(),
		"fs:rw:"+child.String(),
	)

	// Reading a file in the child dir succeeds (child rw overrides parent none).
	s.whenRun("cat", childFile)
	s.thenExitCode(0)
	s.thenStdoutContains("child content")

	// Writing a new file in the child dir succeeds (override is truly rw, not just readable).
	s.whenRun("sh", "-c", "echo written > "+child.join("new.txt"))
	s.thenExitCode(0)

	// Listing the none-directory is denied.
	s.whenRun("ls", parent.String())
	s.thenExitCodeNonZero()
	s.thenStderrContains("parent': Permission denied")

	// Reading a file directly in the none-directory is also denied: files in it are not
	// mounted at all, so they appear absent.
	s.whenRun("cat", parentFile)
	s.thenExitCodeNonZero()
	s.thenStderrContains("direct.txt: No such file or directory")
}

func Test_SandboxingFilesystem_RelativePathsInRulesResolvedRelativeToConfigDirectory(t *testing.T) {
	// Relative paths in rules resolve relative to the config file's directory,
	// not the CWD from which execave is invoked.

	t.Run("config-dir equals cwd", func(t *testing.T) {
		s := newScenario(t)
		work := s.givenDir("work")
		src := s.givenDir("work/src")
		testFile := src.file("test.txt", "hello")

		s.givenRulesInDir(work.String(), "fs:ro:./src")
		s.whenRunWithDefaultConfig(work.String(), "cat", testFile)

		s.thenExitCode(0)
		s.thenStdoutContains("hello")
	})

	t.Run("config-dir differs from cwd", func(t *testing.T) {
		// Even when execave is invoked from a different CWD, ./src resolves to
		// conf/src — proving resolution is config-relative, not CWD-relative.
		s := newScenario(t)
		conf := s.givenDir("conf")
		src := s.givenDir("conf/src")
		testFile := src.file("test.txt", "hello")

		s.givenRulesInDir(conf.String(), "fs:ro:./src")
		s.whenRun("cat", testFile)

		s.thenExitCode(0)
		s.thenStdoutContains("hello")
	})

	t.Run("cwd-relative path not mounted", func(t *testing.T) {
		// A same-named dir under a different base is not mounted: the rule resolves
		// to conf/src, not to any other/src that may exist relative to CWD.
		s := newScenario(t)
		conf := s.givenDir("conf")
		s.givenDir("conf/src")
		other := s.givenDir("other")
		otherFile := other.file("src/data.txt", "cwd data")

		s.givenRulesInDir(conf.String(), "fs:ro:./src")
		s.whenRun("cat", otherFile)

		s.thenExitCodeNonZero()
		s.thenStderrContains("No such file or directory")
	})

	t.Run("parent-traversal relative path", func(t *testing.T) {
		// ../data in a config at proj/conf/ resolves to proj/data.
		s := newScenario(t)
		data := s.givenDir("proj/data")
		testFile := data.file("config.txt", "data content")
		confDir := s.givenDir("proj/conf")

		s.givenRulesInDir(confDir.String(), "fs:ro:../data")
		s.whenRun("cat", testFile)

		s.thenExitCode(0)
		s.thenStdoutContains("data content")
	})
}

func Test_SandboxingFilesystem_InterpreterAutoMountEnablesDynamicallyLinkedBinary(t *testing.T) {
	// execave auto-mounts bwrap's ELF interpreter as a synthetic rule so dynamically
	// linked binaries work even when the interpreter path is absent from the user's config.
	s := newScenario(t)
	// Mount /usr and the linker cache but NOT /lib64, where the interpreter symlink
	// (ld-linux-x86-64.so.2) typically lives.
	s.givenRulesOnly(
		"fs:ro:/usr",
		"fs:ro:/etc/ld.so.cache",
		"env:pass:PATH",
	)

	s.whenRun("ls", "/usr/bin")

	s.thenExitCode(0)
}

func Test_SandboxingFilesystem_SandboxedProcessReceivesTerminalResizeSignal(t *testing.T) {
	// On kernels where TIOCSTI is blocked, execave omits --new-session so the sandboxed
	// process stays in the terminal's process group and receives SIGWINCH on resize.
	failIfNoBwrap(t)

	data, err := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	require.NoError(t, err, "/proc/sys/dev/tty/legacy_tiocsti not available (pre-6.2 kernel)")

	if strings.TrimSpace(string(data)) != "0" {
		t.Skipf("TIOCSTI not blocked by kernel (expected '0', got '%s')", strings.TrimSpace(string(data)))
	}

	tmpDir := testTempDir(t)
	signalFile := filepath.Join(tmpDir, "signal-received")
	scriptFile := filepath.Join(tmpDir, "trap-sigwinch.sh")

	script := fmt.Sprintf(`#!/bin/bash
trap 'echo "received" > %[1]s && exit 0' WINCH
for i in {1..50}; do
  sleep 0.1
  [ -f %[1]s ] && exit 0
done
exit 1`, signalFile)
	createFile(t, scriptFile, script)

	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	configPath := writeConfig(t, rules)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "--config", configPath, "--", "bash", scriptFile) //#nosec G204 -- test code intentionally launches binary with test-controlled args
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	require.NoError(t, cmd.Start())

	// Give the sandbox time to start and set up the signal handler.
	time.Sleep(500 * time.Millisecond)

	require.NoError(t, syscall.Kill(-cmd.Process.Pid, syscall.SIGWINCH))

	err = cmd.Wait()
	require.NoError(t, err)

	data, err = os.ReadFile(signalFile) //#nosec G304 -- test-controlled file path in temp directory
	require.NoError(t, err)
	assert.Contains(t, string(data), "received")
}
