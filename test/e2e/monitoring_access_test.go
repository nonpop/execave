package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MonitoringAccess_DefaultOutputIsStderr(t *testing.T) {
	// Monitor without --output-path writes access log entries to stderr, not stdout.

	tests := []struct {
		name     string
		action   string
		flags    []string
		wantOp   string
		wantCode int
	}{
		{name: "DENY with default view", action: "none", flags: nil, wantOp: "DENY", wantCode: 1},
		{name: "OK with --show-allowed", action: "ro", flags: []string{"--show-allowed"}, wantOp: "OK", wantCode: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			dir := s.givenDir("data")
			filePath := dir.file("file.txt", "content")
			s.givenRules("fs:" + tt.action + ":" + dir.String())
			s.whenRunTextLogWithFlags(tt.flags, "cat", filePath)
			s.thenExitCode(tt.wantCode)
			s.thenStderrHasEntry("READ", dir.rel("file.txt"), tt.wantOp)
			assert.NotContains(t, s.lastResult.Stdout, dir.rel("file.txt"))
		})
	}
}

func Test_MonitoringAccess_ViewAccessLogInTextOutput(t *testing.T) {
	// Monitor writes access log entries with all four columns (operation, target, result, rule)
	// to stderr. Target paths are shortened relative to the config directory. Rules appear
	// verbatim as written in the config, including tilde form.

	t.Run("path relative to config dir", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("sub/file.txt", "content")
		s.givenRulesInDir(data.String(), "fs:ro:"+data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

		s.thenExitCode(0)
		// Path shown relative to config dir, not as ~/... absolute form
		s.thenStderrHasEntry("READ", "sub/file.txt", "OK", "ro:"+data.String())
		s.thenStderrNotContains(data.rel("sub/file.txt"))
	})

	t.Run("absolute path outside home dir", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "content")
		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

		s.thenExitCode(0)
		// /etc/ld.so.cache is outside home dir; appears with absolute path (no ~/... prefix)
		s.thenStderrHasEntry("READ", "/etc/ld.so.cache", "OK", "ro:/etc/ld.so.cache")
	})

	t.Run("rule shown verbatim with tilde", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "content")

		homeDir, err := os.UserHomeDir()
		require.NoError(t, err)
		rel, err := filepath.Rel(homeDir, data.String())
		require.NoError(t, err)
		tildeRule := "~/" + rel

		s.givenRules("fs:ro:" + tildeRule)

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK", "ro:"+tildeRule)
	})
}

func Test_MonitoringAccess_MonitorNetworkAccess(t *testing.T) {
	// Monitor with net rules logs both plain HTTP and HTTPS (CONNECT-tunneled) requests
	// as HTTP operations, showing endpoint, result, and matched rule.

	t.Run("HTTPS and HTTP requests appear as HTTP operations when allowed", func(t *testing.T) {
		s := newScenario(t)
		s.givenCurl()

		https := s.givenHTTPSServer("NET_HTTPS_OK")
		httpSrv := s.givenHTTPServer("NET_HTTP_OK")

		s.givenRules(
			"net:http:"+https.addr(),
			"net:http:"+httpSrv.addr(),
		)

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", fmt.Sprintf("curl -sk https://%s/ && curl -sf http://%s/",
				https.hostPort(), httpSrv.hostPort()))

		s.thenExitCode(0)
		s.thenStderrHasEntry("HTTP", https.addr(), "OK", "http:"+https.addr())
		s.thenStderrHasEntry("HTTP", httpSrv.addr(), "OK", "http:"+httpSrv.addr())
	})

	t.Run("denied HTTPS request logged as HTTP DENY", func(t *testing.T) {
		s := newScenario(t)
		s.givenCurl()

		srv := s.givenHTTPSServer("should not see this")
		s.givenRules() // no net rules

		s.whenRunTextLog("",
			"curl", "-sk", "--max-time", "5", fmt.Sprintf("https://%s/", srv.hostPort()))

		s.thenStderrHasEntry("HTTP", srv.addr(), "DENY", "no-matching-rule")
	})
}

func Test_MonitoringAccess_MonitorBothFilesystemAndNetworkConcurrently(t *testing.T) {
	// Both filesystem and network monitoring work concurrently in the same session.
	// FS and net monitoring subsystems are independent: a deny in one does not suppress
	// logging in the other.

	tests := []struct {
		name          string
		fsAction      string
		withNetRule   bool
		wantFSResult  string
		wantNetResult string
	}{
		{name: "both allowed", fsAction: "ro", withNetRule: true, wantFSResult: "OK", wantNetResult: "OK"},
		{name: "both denied", fsAction: "none", withNetRule: false, wantFSResult: "DENY", wantNetResult: "DENY"},
		{name: "fs allowed net denied", fsAction: "ro", withNetRule: false, wantFSResult: "OK", wantNetResult: "DENY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenCurl()

			srv := s.givenHTTPServer("CONCURRENT_OK")
			data := s.givenDir("data")
			dataFile := data.file("data.txt", "fs data")

			fsRule := "fs:" + tt.fsAction + ":" + data.String()
			if tt.withNetRule {
				s.givenRules(fsRule, "net:http:"+srv.addr())
			} else {
				s.givenRules(fsRule)
			}

			s.whenRunTextLogWithFlags([]string{"--show-allowed"},
				"sh", "-c", fmt.Sprintf("cat %s || true; curl -sf http://%s/ || true", dataFile, srv.hostPort()))

			s.thenStderrHasEntry("READ", data.rel("data.txt"), tt.wantFSResult)
			s.thenStderrHasEntry("HTTP", srv.addr(), tt.wantNetResult)
		})
	}
}

func Test_MonitoringAccess_MonitorWithoutNetRules(t *testing.T) {
	// With no net rules configured, the proxy still starts and all proxy-aware
	// network requests (HTTP and HTTPS) are denied and logged.

	tests := []struct {
		name     string
		useHTTPS bool
	}{
		{name: "plain HTTP denied and logged", useHTTPS: false},
		{name: "HTTPS CONNECT denied and logged", useHTTPS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenCurl()
			s.givenRules() // no net rules

			var srv testServer
			var curlArgs []string
			if tt.useHTTPS {
				srv = s.givenHTTPSServer("should not see this")
				curlArgs = []string{"-sk", "--max-time", "5", fmt.Sprintf("https://%s/", srv.hostPort())}
			} else {
				srv = s.givenHTTPServer("should not see this")
				curlArgs = []string{"-sf", "--max-time", "5", fmt.Sprintf("http://%s/", srv.hostPort())}
			}

			s.whenRunTextLog("", append([]string{"curl"}, curlArgs...)...)

			s.thenStderrHasEntry("HTTP", srv.addr(), "DENY", "no-matching-rule")
		})
	}
}

func Test_MonitoringAccess_AccessLogAfterSIGINT(t *testing.T) { //nolint:funlen // e2e scenario test
	// SIGINT is forwarded to the sandboxed process (exit code 130) and log entries
	// collected before the interrupt are preserved in the output.
	failIfNoBwrap(t)
	failIfNoStrace(t)

	startAndInterrupt := func(t *testing.T, args []string) (int, string) {
		t.Helper()
		var stderrBuf strings.Builder
		//nolint:gosec // G204: test uses controlled input from test fixtures
		cmd := exec.CommandContext(context.Background(), binaryPath, args...)
		cmd.Stderr = &stderrBuf
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		require.NoError(t, cmd.Start())
		time.Sleep(500 * time.Millisecond)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		waitErr := cmd.Wait()
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				return exitErr.ExitCode(), stderrBuf.String()
			}
		}
		return 0, stderrBuf.String()
	}

	t.Run("log to file preserves entries before interrupt", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "content")
		s.givenRules("fs:ro:" + data.String())

		logFile := filepath.Join(s.tmpDir, "access.log")
		exitCode, _ := startAndInterrupt(t, []string{
			"--config", s.configPath, "monitor",
			"--output-path=" + logFile, "--show-allowed",
			"--", "sh", "-c", "cat " + filePath + " && sleep 60",
		})

		assert.Equal(t, 130, exitCode)
		s.thenFileContains(logFile, "READ")
		s.thenFileContains(logFile, data.rel("file.txt"))
	})

	t.Run("stderr preserves entries before interrupt", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "content")
		s.givenRules("fs:ro:" + data.String())

		exitCode, stderr := startAndInterrupt(t, []string{
			"--config", s.configPath, "monitor", "--show-allowed",
			"--", "sh", "-c", "cat " + filePath + " && sleep 60",
		})

		assert.Equal(t, 130, exitCode)
		assert.Contains(t, stderr, "READ")
		assert.Contains(t, stderr, data.rel("file.txt"))
	})

	t.Run("no accesses exits cleanly with code 130", func(t *testing.T) {
		s := newScenario(t)
		s.givenRules()

		logFile := filepath.Join(s.tmpDir, "access.log")
		exitCode, _ := startAndInterrupt(t, []string{
			"--config", s.configPath, "monitor",
			"--output-path=" + logFile,
			"--", "sleep", "60",
		})

		assert.Equal(t, 130, exitCode)
	})
}

func Test_MonitoringAccess_LogDeduplication(t *testing.T) {
	// Each unique (operation, target) pair appears at most once in the log even when the
	// same resource is accessed multiple times. READ and WRITE on the same path are distinct
	// pairs and both appear.

	t.Run("repeated reads produce one entry", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		testFile := data.file("file.txt", "content")
		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)

		s.thenExitCode(0)
		// Path appears exactly once despite three reads
		assert.Equal(t, 1, strings.Count(s.lastResult.Stderr, data.rel("file.txt")))
	})

	t.Run("read and write on same path are distinct pairs", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		testFile := data.file("file.txt", "content")
		s.givenRules("fs:rw:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", "cat "+testFile+" && echo x >> "+testFile)

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK")
		s.thenStderrHasEntry("WRITE", data.rel("file.txt"), "OK")
	})

	t.Run("repeated denied accesses produce one entry", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		testFile := data.file("file.txt", "content")
		s.givenRules("fs:none:" + data.String())

		s.whenRunTextLog("",
			"sh", "-c", "cat "+testFile+" || true && cat "+testFile+" || true")

		// Path appears exactly once despite two denied accesses
		assert.Equal(t, 1, strings.Count(s.lastResult.Stderr, data.rel("file.txt")))
	})

	t.Run("symlinks to same target deduplicated", func(t *testing.T) {
		s := newScenario(t)
		mount := s.givenDir("mount")
		mount.file("target.txt", "content")
		link1 := mount.join("link1.txt")
		link2 := mount.join("link2.txt")
		s.givenSymlink(mount.join("target.txt"), link1)
		s.givenSymlink(mount.join("target.txt"), link2)

		s.givenRules("fs:ro:" + mount.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", "cat "+link1+" && cat "+link2)

		s.thenExitCode(0)
		// Target appears once despite being resolved through two different symlinks
		assert.Equal(t, 1, strings.Count(s.lastResult.Stderr, mount.rel("target.txt")))
	})
}

func Test_MonitoringAccess_SymlinkResolutionHopsLogged(t *testing.T) { //nolint:funlen // e2e scenario test
	// Each hop in a symlink resolution chain is logged as a separate READ entry.

	t.Run("single hop all allowed", func(t *testing.T) {
		s := newScenario(t)
		mount := s.givenDir("mount")
		targetPath := mount.file("real.txt", "target content")
		linkPath := mount.join("link.txt")
		s.givenSymlink(targetPath, linkPath)

		s.givenRules("fs:ro:" + mount.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", linkPath)

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", mount.rel("link.txt"), "OK", "ro:"+mount.String())
		s.thenStderrHasEntry("READ", mount.rel("real.txt"), "OK", "ro:"+mount.String())
	})

	t.Run("symlink allowed target denied", func(t *testing.T) {
		s := newScenario(t)
		linkDir := s.givenDir("links")
		targetDir := s.givenDir("targets")
		targetPath := targetDir.file("real.txt", "target content")
		linkPath := linkDir.join("link.txt")
		s.givenSymlink(targetPath, linkPath)

		s.givenRules("fs:ro:"+linkDir.String(), "fs:none:"+targetDir.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", linkPath)

		s.thenStderrHasEntry("READ", linkDir.rel("link.txt"), "OK", "ro:"+linkDir.String())
		s.thenStderrHasEntry("READ", targetDir.rel("real.txt"), "DENY", "none:"+targetDir.String())
	})

	t.Run("multi-hop chain all allowed", func(t *testing.T) {
		s := newScenario(t)
		mount := s.givenDir("mount")
		targetPath := mount.file("real.txt", "target content")
		link2Path := mount.join("link2.txt")
		link1Path := mount.join("link1.txt")
		s.givenSymlink(targetPath, link2Path)
		s.givenSymlink(link2Path, link1Path)

		s.givenRules("fs:ro:" + mount.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", link1Path)

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", mount.rel("link1.txt"), "OK", "ro:"+mount.String())
		s.thenStderrHasEntry("READ", mount.rel("link2.txt"), "OK", "ro:"+mount.String())
		s.thenStderrHasEntry("READ", mount.rel("real.txt"), "OK", "ro:"+mount.String())
	})

	t.Run("dir symlink in intermediate path resolved", func(t *testing.T) {
		s := newScenario(t)
		mount := s.givenDir("mount")
		mount.file("realsub/file.txt", "content")
		s.givenSymlink(mount.join("realsub"), mount.join("linksub"))

		s.givenRules("fs:ro:" + mount.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", mount.join("linksub", "file.txt"))

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", mount.rel("linksub"), "OK", "ro:"+mount.String())
		s.thenStderrHasEntry("READ", mount.rel("realsub/file.txt"), "OK", "ro:"+mount.String())
	})

	t.Run("rule boundary is a dir symlink", func(t *testing.T) {
		s := newScenario(t)
		realDir := s.givenDir("real")
		realDir.file("file.txt", "content")

		link := testDir(filepath.Join(s.tmpDir, "link"))
		s.givenSymlink(realDir.String(), link.String())

		// Rule points to the symlink, not the real dir
		s.givenRules("fs:ro:" + link.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", link.join("file.txt"))

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", link.rel("file.txt"), "OK", "ro:"+link.String())
		// The real (resolved) path must NOT appear in the log
		s.thenStderrNotContains(realDir.rel("file.txt"))
	})

	t.Run("rule boundary is a dir symlink with nested subdirectory", func(t *testing.T) {
		s := newScenario(t)
		realDir := s.givenDir("real")
		realDir.file("sub/file.txt", "content")

		link := testDir(filepath.Join(s.tmpDir, "link"))
		s.givenSymlink(realDir.String(), link.String())

		// Rule points to the symlink, not the real dir
		s.givenRules("fs:ro:" + link.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", link.join("sub", "file.txt"))

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", link.rel("sub/file.txt"), "OK", "ro:"+link.String())
		// The real (resolved) path must NOT appear in the log
		s.thenStderrNotContains(realDir.rel("sub/file.txt"))
	})

	t.Run("symlink target in managed path logged as UNKNOWN", func(t *testing.T) {
		// A symlink in a ruled directory whose target lands in a managed path (e.g. /tmp,
		// which is a fresh sandbox-owned tmpfs) cannot be matched against user rules.
		// The monitor logs the hop as UNKNOWN with symlink-target-unresolvable.
		s := newScenario(t)
		data := s.givenDir("data")
		s.givenRules("fs:rw:" + data.String())

		// Inside the sandbox, /tmp is a managed path. Create a file there, symlink to it
		// from the ruled directory, then read through the symlink.
		linkPath := data.join("link.txt")
		s.whenRunTextLog("", "sh", "-c",
			"echo hello > /tmp/managed-target.txt && ln -s /tmp/managed-target.txt "+linkPath+" && cat "+linkPath)

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", data.rel("link.txt"), "UNKNOWN", "symlink-target-unresolvable")
	})
}

func Test_MonitoringAccess_WriteThroughSymlinkLogsHopAndTarget(t *testing.T) {
	// Writing through a symlink logs the hop as a READ and the resolved target as a WRITE.
	// The result for each entry depends on the rule covering its directory.

	tests := []struct {
		name       string
		linkRule   string
		targetRule string
	}{
		{name: "within single rw mount", linkRule: "rw", targetRule: "rw"},
		{name: "ro link dir to rw target dir", linkRule: "ro", targetRule: "rw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			linkDir := s.givenDir("links")
			targetDir := s.givenDir("targets")
			targetDir.file("target.txt", "old")
			linkPath := linkDir.join("link.txt")
			s.givenSymlink(targetDir.join("target.txt"), linkPath)

			s.givenRules("fs:"+tt.linkRule+":"+linkDir.String(), "fs:"+tt.targetRule+":"+targetDir.String())

			s.whenRunTextLogWithFlags([]string{"--show-allowed"},
				"sh", "-c", "echo new > "+linkPath)

			s.thenExitCode(0)
			s.thenStderrHasEntry("READ", linkDir.rel("link.txt"), "OK", tt.linkRule+":"+linkDir.String())
			s.thenStderrHasEntry("WRITE", targetDir.rel("target.txt"), "OK", tt.targetRule+":"+targetDir.String())
		})
	}
}

func Test_MonitoringAccess_VerifyFilesystemEnforcementDecisionsAreAccuratelyLogged(t *testing.T) {
	// READ and WRITE operations are logged with the result matching actual enforcement:
	// OK when the sandbox permitted the access, DENY when it blocked it.

	t.Run("read allowed by ro rule", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "file content")
		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

		s.thenExitCode(0)
		s.thenStdoutContains("file content")
		s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK", "ro:"+data.String())
	})

	t.Run("read denied by none rule", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "file content")
		s.givenRules("fs:none:" + data.String())

		s.whenRunTextLog("", "cat", filePath)

		s.thenExitCodeNonZero()
		s.thenStderrHasEntry("READ", data.rel("file.txt"), "DENY", "none:"+data.String())
	})

	t.Run("write allowed by rw rule", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "original")
		s.givenRules("fs:rw:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "sh", "-c", "echo appended >> "+filePath)

		s.thenExitCode(0)
		content, err := os.ReadFile(filePath) // #nosec G304 -- test-controlled path
		require.NoError(t, err)
		assert.Contains(t, string(content), "appended")
		s.thenStderrHasEntry("WRITE", data.rel("file.txt"), "OK", "rw:"+data.String())
	})

	t.Run("write denied by ro rule", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "original")
		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLog("", "sh", "-c", "echo appended >> "+filePath)

		s.thenExitCodeNonZero()
		content, err := os.ReadFile(filePath) // #nosec G304 -- test-controlled path
		require.NoError(t, err)
		assert.Equal(t, "original", string(content))
		s.thenStderrHasEntry("WRITE", data.rel("file.txt"), "DENY", "ro:"+data.String())
	})
}

func Test_MonitoringAccess_VerifyNetworkEnforcementDecisionsAreAccuratelyLogged(t *testing.T) {
	// Allowed HTTP and HTTPS requests appear as HTTP OK with the matched rule,
	// and explicitly denied requests appear as HTTP DENY, matching actual proxy enforcement.
	tests := []struct {
		name       string
		useHTTPS   bool
		action     string
		wantResult string
	}{
		{name: "plain HTTP allowed by http rule", useHTTPS: false, action: "http", wantResult: "OK"},
		{name: "plain HTTP denied by none rule", useHTTPS: false, action: "none", wantResult: "DENY"},
		{name: "HTTPS allowed by http rule", useHTTPS: true, action: "http", wantResult: "OK"},
		{name: "HTTPS denied by none rule", useHTTPS: true, action: "none", wantResult: "DENY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenCurl()

			var srv testServer
			var curlArgs []string
			if tt.useHTTPS {
				srv = s.givenHTTPSServer("ENFORCE_BODY")
				curlArgs = []string{"curl", "-sk", fmt.Sprintf("https://%s/", srv.hostPort())}
			} else {
				srv = s.givenHTTPServer("ENFORCE_BODY")
				curlArgs = []string{"curl", "-s", fmt.Sprintf("http://%s/", srv.hostPort())}
			}

			rule := tt.action + ":" + srv.addr()
			s.givenRules("net:" + rule)

			s.whenRunTextLogWithFlags([]string{"--show-allowed"}, curlArgs...)

			if tt.wantResult == "OK" {
				s.thenStdoutContains("ENFORCE_BODY")
			}
			s.thenStderrHasEntry("HTTP", srv.addr(), tt.wantResult, rule)
		})
	}
}

func Test_MonitoringAccess_MonitorReflectsFilesystemRulePrecedenceCorrectly(t *testing.T) {
	// When a more-specific child rule overlaps a broader parent rule, the monitor attributes
	// each access to the winning rule: the child rule for paths it covers, the parent for
	// paths it does not.
	s := newScenario(t)
	project := s.givenDir("project")
	gitDir := project.join(".git")
	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)

	projectFile := project.file("main.go", "package main")
	gitFile := project.file(".git/config", "[core]")

	s.givenRules("fs:rw:"+project.String(), "fs:ro:"+gitDir)

	// Run all operations in one invocation to capture all in the same log
	cmd := "echo '// comment' >> " + projectFile + " && " +
		"cat " + gitFile + " && " +
		"(echo 'modified' >> " + gitFile + " || true)"
	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "sh", "-c", cmd)

	// First two operations succeed, last one fails
	s.thenExitCode(0)
	s.thenStderrHasEntry("WRITE", project.rel("main.go"), "OK", "rw:"+project.String())
	s.thenStderrHasEntry("READ", project.rel(".git/config"), "OK", "ro:"+gitDir)
	s.thenStderrHasEntry("WRITE", project.rel(".git/config"), "DENY", "ro:"+gitDir)
}

func Test_MonitoringAccess_MonitorReflectsNetworkRulePrecedenceCorrectly(t *testing.T) { //nolint:funlen // e2e scenario test
	t.Run("specific deny overrides broad CIDR allow", func(t *testing.T) {
		// When a broad CIDR allow and a more-specific IP/port deny overlap, the specific
		// deny wins. Requests to the unoverridden port show OK with the broad rule; requests
		// to the specifically-denied port show DENY with the narrow rule.
		s := newScenario(t)
		s.givenCurl()

		allowed := s.givenHTTPServer("ALLOWED_CIDR")
		denied := s.givenHTTPServer("should not see this")

		s.givenRules(
			"net:http:127.0.0.0/8:*",
			"net:none:127.0.0.1/32:"+denied.port,
		)

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", fmt.Sprintf(
				"curl -sf http://%s/ || true; curl -sf http://%s/ || true",
				allowed.hostPort(), denied.hostPort()))

		s.thenStderrHasEntry("HTTP", allowed.addr(), "OK", "http:127.0.0.0/8:*")
		s.thenStderrHasEntry("HTTP", denied.addr(), "DENY", "none:127.0.0.1/32:"+denied.port)
	})

	t.Run("specific allow overrides broad CIDR deny", func(t *testing.T) {
		// When a broad CIDR deny and a more-specific IP/port allow overlap, the specific
		// allow wins. Requests to the specifically-allowed port show OK with the narrow rule;
		// requests to other ports show DENY with the broad rule.
		s := newScenario(t)
		s.givenCurl()

		allowed := s.givenHTTPServer("ALLOWED_SPECIFIC")
		denied := s.givenHTTPServer("should not see this")

		s.givenRules(
			"net:none:127.0.0.0/8:*",
			"net:http:127.0.0.1/32:"+allowed.port,
		)

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", fmt.Sprintf(
				"curl -sf http://%s/ || true; curl -sf http://%s/ || true",
				allowed.hostPort(), denied.hostPort()))

		s.thenStderrHasEntry("HTTP", allowed.addr(), "OK", "http:127.0.0.1/32:"+allowed.port)
		s.thenStderrHasEntry("HTTP", denied.addr(), "DENY", "none:127.0.0.0/8:*")
	})

	t.Run("unmatched request shows default deny", func(t *testing.T) {
		// When a request matches no rule, the access log records "no-matching-rule" to
		// distinguish default deny from an explicit none rule. Both wrong-port and
		// different-host cases produce the same default deny entry.
		s := newScenario(t)
		s.givenCurl()

		allowed := s.givenHTTPServer("ALLOWED")

		s.givenRules("net:http:127.0.0.1/32:" + allowed.port)

		s.whenRunTextLogWithFlags([]string{"--show-allowed"},
			"sh", "-c", fmt.Sprintf(
				"curl -sf http://%s/ || true; curl -sf http://192.0.2.1:9999/ || true",
				allowed.hostPort()))

		s.thenStderrHasEntry("HTTP", allowed.addr(), "OK", "http:127.0.0.1/32:"+allowed.port)
		s.thenStderrHasEntry("HTTP", "192.0.2.1:9999", "DENY", "no-matching-rule")
	})

	t.Run("domain-based deny rule blocks matching traffic", func(t *testing.T) {
		// A net:none rule for a domain denies matching traffic before DNS resolution;
		// the access log records the exact rule string, confirming it was an explicit deny.
		s := newScenario(t)
		s.givenCurl()

		s.givenRules("net:none:evil.com:443")

		s.whenRunTextLogWithFlags(nil,
			"sh", "-c", "curl -sf http://evil.com:443/ || true")

		s.thenStderrHasEntry("HTTP", "evil.com:443", "DENY", "none:evil.com:443")
	})
}

func Test_MonitoringAccess_BarePathRelativeAccessesResolvedInAccessLog(t *testing.T) {
	// Bare-path syscalls (e.g., access()) with relative paths are resolved to absolute paths
	// using tracked per-pid cwd, producing proper rule matching (OK or DENY) instead of UNKNOWN.

	tests := []struct {
		name         string
		gitDirAction string
		wantResult   string
	}{
		{name: "allowed by ro rule", gitDirAction: "ro", wantResult: "OK"},
		{name: "denied by none rule", gitDirAction: "none", wantResult: "DENY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenGcc()

			project := s.givenDir("project")
			project.file(".git/config", "[core]")
			gitDir := project.join(".git")

			cSource := filepath.Join(s.tmpDir, "access_test.c")
			cBinary := filepath.Join(s.tmpDir, "access_test")
			// Binary chdirs to argv[1] (tracked by strace), then calls bare-path access().
			createFile(t, cSource, "#include <unistd.h>\nint main(int argc, char *argv[]) { if (argc > 1) chdir(argv[1]); access(\".git/config\", R_OK); return 0; }\n")

			//nolint:gosec // G204: test code with controlled args
			gccCmd := exec.CommandContext(context.Background(), "gcc", "-o", cBinary, cSource)
			require.NoError(t, gccCmd.Run())

			// Binary is in tmpDir (ro); .git dir uses tt.gitDirAction (project itself stays ro).
			s.givenRules(
				"fs:ro:"+testDir(s.tmpDir).String(),
				"fs:"+tt.gitDirAction+":"+gitDir,
			)

			s.whenRunTextLogWithFlags([]string{"--show-allowed"},
				cBinary, project.String())

			s.thenStderrHasEntry("READ", project.rel(".git/config"), tt.wantResult,
				tt.gitDirAction+":"+gitDir)
		})
	}
}

func Test_MonitoringAccess_UnresolvedRelativePathWhenNoCwdTracked(t *testing.T) { //nolint:funlen // e2e scenario test
	// A bare-path relative syscall issued before execave tracks the pid's cwd produces an
	// UNKNOWN entry with rule "unresolved-relative-path" instead of being silently dropped.
	// Both the AT_FDCWD variant (access syscall) and the numeric dirfd variant (openat with
	// a bad fd) produce UNKNOWN because no cwd can be resolved.
	requireAMD64(t)

	tests := []struct {
		name     string
		src      string
		wantPath string
	}{
		{
			name: "AT_FDCWD variant",
			src: `
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
	sys_access("untracked-relative/file.txt", 0);
	sys_exit(0);
}
`,
			wantPath: "untracked-relative/file.txt",
		},
		{
			name: "numeric dirfd variant",
			src: `
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
`,
			wantPath: "fd-relative.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenGcc()

			cSource := filepath.Join(s.tmpDir, "bare.c")
			cBinary := filepath.Join(s.tmpDir, "bare")
			createFile(t, cSource, tt.src)
			//nolint:gosec // G204: test code with controlled args
			cmd := exec.CommandContext(context.Background(), "gcc", "-nostdlib", "-static", "-o", cBinary, cSource)
			require.NoError(t, cmd.Run())

			s.givenRules("fs:ro:" + testDir(s.tmpDir).String())
			s.whenRunTextLog("", cBinary)

			s.thenExitCode(0)
			s.thenStderrHasEntry("READ", tt.wantPath, "UNKNOWN", "unresolved-relative-path")
		})
	}
}

func Test_MonitoringAccess_NonExistentReadFilteredFromLog(t *testing.T) {
	t.Run("read of non-existent file is filtered", func(t *testing.T) {
		// Reads of non-existent files are filtered from the access log (noise reduction).
		// --show-allowed confirms the filtering is at the noise-reduction level, not the view level.
		s := newScenario(t)
		data := s.givenDir("data")

		s.givenRules("fs:ro:" + data.String())

		// cat a file that does not exist — the monitor should filter it (noise reduction)
		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", data.join("noexist.txt"))

		s.thenExitCode(1)
		s.thenStderrNotContains(data.rel("noexist.txt"))
	})

	t.Run("write to non-existent file is not filtered", func(t *testing.T) {
		// The non-existent path filter applies only to reads; writes to non-existent
		// files must still appear in the access log.
		s := newScenario(t)
		data := s.givenDir("data")

		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "sh", "-c", "echo hello > "+data.join("newfile.txt")+" || true")

		s.thenExitCode(0)
		s.thenStderrHasEntry("WRITE", data.rel("newfile.txt"), "DENY")
	})

	t.Run("read with lstat error other than ENOENT is not filtered", func(t *testing.T) {
		// When the monitor cannot determine if a path exists (e.g. EACCES on parent
		// directory), the access is still logged — fail-safe: when in doubt, log it.
		s := newScenario(t)
		data := s.givenDir("data")
		restricted := filepath.Join(data.String(), "restricted")
		require.NoError(t, os.MkdirAll(restricted, 0o750))
		secretFile := data.file("restricted/secret.txt", "secret")
		require.NoError(t, os.Chmod(restricted, 0o000))
		t.Cleanup(func() {
			_ = os.Chmod(restricted, 0o750) //nolint:gosec // Restore permissions for cleanup
		})

		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "sh", "-c", "cat "+secretFile+" || true")

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", data.rel("restricted/secret.txt"))
	})
}

func Test_MonitoringAccess_DeniedOnlyDefaultView(t *testing.T) {
	// Default monitor view shows only DENY (and UNKNOWN) entries; OK entries are
	// filtered out unless --show-allowed is used.

	t.Run("allowed access produces no entry", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		data.file("file.txt", "test data")
		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLog("", "cat", data.join("file.txt"))

		s.thenExitCode(0)
		s.thenStderrNotContains(data.rel("file.txt"))
	})

	t.Run("mixed: denied entry visible, allowed entry absent", func(t *testing.T) {
		s := newScenario(t)
		allowed := s.givenDir("allowed")
		denied := s.givenDir("denied")
		allowed.file("ok.txt", "allowed content")
		denied.file("secret.txt", "secret content")
		s.givenRules("fs:ro:"+allowed.String(), "fs:none:"+denied.String())

		s.whenRunTextLog("",
			"sh", "-c", "cat "+allowed.join("ok.txt")+" || true; cat "+denied.join("secret.txt")+" || true")

		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", denied.rel("secret.txt"), "DENY")
		s.thenStderrNotContains(allowed.rel("ok.txt"))
	})
}

func Test_MonitoringAccess_ObserveNativeNetworkAccessesWithoutIsolation(t *testing.T) {
	// In no-sandbox monitor mode, proxy-aware network traffic is observed but never blocked.
	// Network entries must be logged as UNENFORCED, even with no matching rule.

	failIfNoStrace(t)

	t.Run("http without net rules", func(t *testing.T) {
		s := newScenario(t)
		s.givenCurl()
		srv := s.givenHTTPServer("NATIVE_NET_HTTP_OK")
		// No net rules — proxy starts with deny-all, but in no-sandbox mode it must not block.
		s.givenRules()

		s.whenRunNoSandboxMonitorFile("",
			"curl", "-sf", fmt.Sprintf("http://%s/", srv.hostPort()))

		s.thenExitCode(0)
		s.thenStdoutContains("NATIVE_NET_HTTP_OK")
		s.thenStderrHasEntry("HTTP", srv.addr(), "UNENFORCED", "no-matching-rule")
	})

	t.Run("https without net rules", func(t *testing.T) {
		s := newScenario(t)
		s.givenCurl()
		srv := s.givenHTTPSServer("NATIVE_NET_HTTPS_OK")
		s.givenRules()

		s.whenRunNoSandboxMonitorFile("",
			"curl", "-sk", fmt.Sprintf("https://%s/", srv.hostPort()))

		s.thenExitCode(0)
		s.thenStdoutContains("NATIVE_NET_HTTPS_OK")
		s.thenStderrHasEntry("HTTP", srv.addr(), "UNENFORCED", "no-matching-rule")
	})

	t.Run("explicit deny rule is unenforced", func(t *testing.T) {
		s := newScenario(t)
		s.givenCurl()
		srv := s.givenHTTPServer("NATIVE_NET_DENY_RULE_OK")
		s.givenRules("net:none:" + srv.addr())

		s.whenRunNoSandboxMonitorFile("",
			"curl", "-sf", fmt.Sprintf("http://%s/", srv.hostPort()))

		s.thenExitCode(0)
		s.thenStdoutContains("NATIVE_NET_DENY_RULE_OK")
		s.thenStderrHasEntry("HTTP", srv.addr(), "UNENFORCED", "none:"+srv.addr())
	})
}

func Test_NoSandbox_UnenforcedEntriesAppearInLog(t *testing.T) { //nolint:funlen // e2e scenario test
	// No-sandbox monitor logs filesystem accesses as UNENFORCED regardless of matching rules.
	failIfNoStrace(t)
	tests := []struct {
		name           string
		rules          []string
		ruleDirKey     string
		targetDirKey   string
		targetFile     string
		targetContents string
		wantRuleSub    string
	}{
		{
			name:           "no matching rule",
			rules:          []string{"fs:ro:%s"},
			ruleDirKey:     "data",
			targetDirKey:   "blocked",
			targetFile:     "secret.txt",
			targetContents: "secret",
			wantRuleSub:    "",
		},
		{
			name:           "explicit deny rule",
			rules:          []string{"fs:none:%s"},
			ruleDirKey:     "blocked",
			targetDirKey:   "blocked",
			targetFile:     "secret.txt",
			targetContents: "secret",
			wantRuleSub:    "none:%s",
		},
		{
			name:           "explicit allow rule",
			rules:          []string{"fs:ro:%s"},
			ruleDirKey:     "data",
			targetDirKey:   "data",
			targetFile:     "allowed.txt",
			targetContents: "allowed",
			wantRuleSub:    "ro:%s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			data := s.givenDir("data")
			data.file("allowed.txt", "allowed")
			blocked := s.givenDir("blocked")
			blocked.file("secret.txt", "secret")

			dirByKey := map[string]testDir{
				"data":    data,
				"blocked": blocked,
			}
			targetDir := dirByKey[tt.targetDirKey]
			ruleDir := dirByKey[tt.ruleDirKey]
			targetPath := targetDir.join(tt.targetFile)

			rules := make([]string, 0, len(tt.rules))
			for _, rule := range tt.rules {
				rules = append(rules, fmt.Sprintf(rule, ruleDir.String()))
			}
			s.givenRules(rules...)

			s.whenRunNoSandboxMonitorFile("", "cat", targetPath)

			s.thenExitCode(0)
			s.thenStdoutContains(tt.targetContents)
			s.thenStderrHasEntry("READ", targetDir.rel(tt.targetFile), "UNENFORCED")
			if tt.wantRuleSub != "" {
				s.thenStderrHasEntry(fmt.Sprintf(tt.wantRuleSub, ruleDir.String()))
			}
		})
	}
}

func Test_NoSandbox_WithoutMonitorExitsError(t *testing.T) {
	// Root flags reject --no-sandbox and do not execute the command.
	s := newScenario(t)
	s.givenRules()
	markerPath := filepath.Join(t.TempDir(), "marker.txt")
	result := runExecave(t, "", "--config", s.configPath, "--no-sandbox", "--", "sh", "-c", "echo ran > "+markerPath)
	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "unknown flag: --no-sandbox")
	_, err := os.Stat(markerPath)
	require.Error(t, err)
}

func Test_NoSandbox_WritesLogToFile(t *testing.T) {
	// In no-sandbox monitor mode with --output-path, access log entries go to the file
	// instead of stderr. The entry shows UNENFORCED with the matched rule even when the
	// rule would have denied access.
	failIfNoStrace(t)
	s := newScenario(t)
	blocked := s.givenDir("blocked")
	blocked.file("secret.txt", "secret")
	s.givenRules("fs:none:" + blocked.String())

	logFile := filepath.Join(s.tmpDir, "access.log")

	s.whenRunNoSandboxMonitorFile(logFile, "cat", blocked.join("secret.txt"))

	s.thenExitCode(0)
	s.thenFileHasEntry(logFile, "READ", blocked.rel("secret.txt"), "UNENFORCED", "none:"+blocked.String())
	s.thenStderrNotContains(blocked.rel("secret.txt"))
}

// bpfPythonCmd is the python3 one-liner that invokes the bpf syscall (nr 321 on x86_64).
const bpfPythonCmd = "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)"

// bpfRebootPythonCmd invokes bpf and reboot (nr 169) with invalid magic (safe: returns EINVAL).
const bpfRebootPythonCmd = "import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(169,0,0,0)"

// requireAMD64 fails the test on non-x86_64 architectures; only amd64 is supported.
func requireAMD64(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Fatalf("unsupported architecture: %s (only amd64 is supported)", runtime.GOARCH)
	}
}

func Test_MonitoringAccess_ViewSeccompDeniedSyscallAttemptsInAccessLog(t *testing.T) {
	// A blocked syscall attempt appears as a SYSCALL DENY entry in the access log.
	// Each distinct blocked syscall produces its own independent entry.
	requireAMD64(t)

	tests := []struct {
		name         string
		cmd          string
		wantSyscalls []string
	}{
		{
			name:         "single blocked syscall",
			cmd:          bpfPythonCmd,
			wantSyscalls: []string{"bpf"},
		},
		{
			name:         "two different blocked syscalls",
			cmd:          bpfRebootPythonCmd,
			wantSyscalls: []string{"bpf", "reboot"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenPython3()
			s.givenRules()

			s.whenRunTextLog("", "python3", "-c", tt.cmd)

			for _, sc := range tt.wantSyscalls {
				s.thenStderrHasEntry("SYSCALL", sc, "DENY", "no-matching-rule")
			}
		})
	}
}

func Test_MonitoringAccess_VerifySeccompFilterIsActiveByPresenceOfSyscallEntries(t *testing.T) {
	// Sandboxed mode produces SYSCALL DENY entries for blocked syscalls; --no-sandbox produces
	// UNENFORCED entries instead, confirming seccomp is not active outside the sandbox.
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules()

	s.whenRunTextLog("", "python3", "-c", bpfPythonCmd)
	s.thenStderrHasEntry("SYSCALL", "bpf", "DENY", "no-matching-rule")

	s.whenRunTextLogWithFlags([]string{"--no-sandbox"}, "python3", "-c", bpfPythonCmd)
	s.thenStderrHasEntry("UNENFORCED", "SYSCALL", "bpf")
	s.thenStderrNotContains("DENY")
}

func Test_MonitoringAccess_SeccompDeniedSyscallEntriesDeduplicated(t *testing.T) {
	// Repeated attempts of the same blocked syscall produce exactly one SYSCALL DENY
	// entry in the log. Deduplication is per-syscall name: two different blocked syscalls
	// each produce their own single entry.
	requireAMD64(t)

	const bpfTwice = "import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(321,0,0,0)"
	const bpfAndRebootTwice = "import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(321,0,0,0); l.syscall(169,0,0,0); l.syscall(169,0,0,0)"

	tests := []struct {
		name         string
		cmd          string
		wantSyscalls []string
	}{
		{
			name:         "single call",
			cmd:          bpfPythonCmd,
			wantSyscalls: []string{"bpf"},
		},
		{
			name:         "same syscall twice",
			cmd:          bpfTwice,
			wantSyscalls: []string{"bpf"},
		},
		{
			name:         "two different syscalls each called twice",
			cmd:          bpfAndRebootTwice,
			wantSyscalls: []string{"bpf", "reboot"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenPython3()
			s.givenRules()

			s.whenRunTextLog("", "python3", "-c", tt.cmd)

			for _, sc := range tt.wantSyscalls {
				s.thenStderrHasEntry("SYSCALL", sc, "DENY", "no-matching-rule")
				var count int
				for line := range strings.SplitSeq(s.lastResult.Stderr, "\n") {
					if strings.Contains(line, "SYSCALL") && strings.Contains(line, sc) {
						count++
					}
				}
				// Each unique syscall name appears exactly once (deduplication).
				assert.Equal(t, 1, count)
			}
		})
	}
}

func Test_MonitoringAccess_AllowedSyscallLoggedAsOk(t *testing.T) {
	// An explicitly allowed syscall appears as SYSCALL OK with the matched rule when
	// --show-allowed is used, and is absent from the default (DENY-only) view.
	requireAMD64(t)

	t.Run("hidden without --show-allowed", func(t *testing.T) {
		s := newScenario(t)
		s.givenPython3()
		s.givenRules("syscall:allow:bpf")

		s.whenRunTextLog("", "python3", "-c", bpfPythonCmd)

		s.thenStderrNotContains("bpf")
	})

	t.Run("logged as OK with --show-allowed", func(t *testing.T) {
		s := newScenario(t)
		s.givenPython3()
		s.givenRules("syscall:allow:bpf")

		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "python3", "-c", bpfPythonCmd)

		s.thenStderrHasEntry("SYSCALL", "bpf", "OK", "allow:bpf")
	})
}

func Test_MonitoringAccess_ObserveNativeFilesystemAccessesToDiagnoseSandboxFailures(t *testing.T) {
	// --no-sandbox --monitor runs the command without bwrap, logging all filesystem
	// accesses as UNENFORCED. This lets the user observe what paths a program
	// naturally accesses to diagnose why it fails inside the sandbox.
	failIfNoStrace(t)

	t.Run("file denied in sandbox is accessible and logged UNENFORCED", func(t *testing.T) {
		s := newScenario(t)
		dir := s.givenDir("target")
		filePath := dir.file("probe.txt", "native content")
		s.givenRules("fs:none:" + dir.String())

		s.whenRunNoSandboxMonitorFile("", "cat", filePath)

		s.thenExitCode(0)
		s.thenStdoutContains("native content")
		s.thenStderrHasEntry("READ", dir.rel("probe.txt"), "UNENFORCED", "none:"+dir.String())
	})

	t.Run("file with no matching rule is accessible and logged UNENFORCED", func(t *testing.T) {
		s := newScenario(t)
		other := s.givenDir("other")
		other.file("other.txt", "other")
		target := s.givenDir("target")
		filePath := target.file("probe.txt", "native content")
		s.givenRules("fs:ro:" + other.String())

		s.whenRunNoSandboxMonitorFile("", "cat", filePath)

		s.thenExitCode(0)
		s.thenStdoutContains("native content")
		s.thenStderrHasEntry("READ", target.rel("probe.txt"), "UNENFORCED", "no-matching-rule")
	})
}

func Test_MonitoringAccess_WriteNativeAccessLogToFileInRealTime(t *testing.T) {
	// In no-sandbox monitor mode with --output-path, entries are written to the file
	// in real time — before the process exits — so the file can be tailed while running.
	failIfNoStrace(t)

	s := newScenario(t)
	dir := s.givenDir("data")
	filePath := dir.file("file.txt", "content")
	s.givenRules("fs:ro:" + dir.String())

	logFile := filepath.Join(s.tmpDir, "native.log")

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", s.configPath, "monitor", "--no-sandbox",
		"--output-path="+logFile,
		"--", "sh", "-c", "cat "+filePath+" && sleep 60",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	time.Sleep(500 * time.Millisecond)

	// Log file must already contain the READ entry while the process is still sleeping.
	s.thenFileHasEntry(logFile, "READ", dir.rel("file.txt"), "UNENFORCED")

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

func Test_MonitoringAccess_RelativeDirfdResolvesWithAnnotatedPath(t *testing.T) {
	// When strace annotates a numeric dirfd with a directory path, a relative path
	// argument is joined with that fd annotation to produce an absolute logged path.
	s := newScenario(t)
	s.givenGcc()

	data := s.givenDir("data")
	data.file("file.txt", "content")

	cSource := filepath.Join(s.tmpDir, "dirfd_open.c")
	cBinary := filepath.Join(s.tmpDir, "dirfd_open")
	createFile(t, cSource, `
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
`)
	//nolint:gosec // G204: test code with controlled args
	cmd := exec.CommandContext(context.Background(), "gcc", "-o", cBinary, cSource)
	require.NoError(t, cmd.Run())

	s.givenRules("fs:ro:" + testDir(s.tmpDir).String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, cBinary, data.String())

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK")
}

func Test_MonitoringAccess_EmptyPathWithAtEmptyPathResolvesFromFdAnnotation(t *testing.T) {
	// When an *at() syscall uses an empty path argument with a numeric dirfd annotated by
	// strace (AT_EMPTY_PATH usage), the fd's annotated path is logged as the accessed path.
	s := newScenario(t)
	s.givenGcc()

	data := s.givenDir("data")
	filePath := data.file("statme.txt", "content")

	cSource := filepath.Join(s.tmpDir, "at_empty_path.c")
	cBinary := filepath.Join(s.tmpDir, "at_empty_path")
	createFile(t, cSource, `
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
`)
	//nolint:gosec // G204: test code with controlled args
	cmd := exec.CommandContext(context.Background(), "gcc", "-o", cBinary, cSource)
	require.NoError(t, cmd.Run())

	s.givenRules("fs:ro:" + testDir(s.tmpDir).String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, cBinary, filePath)

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", data.rel("statme.txt"), "OK")
}

func Test_MonitoringAccess_FchdirUpdatesCwdForSubsequentRelativePaths(t *testing.T) {
	// A successful fchdir() call updates the monitored pid's tracked cwd so that
	// subsequent bare-path syscalls resolve against the new directory.
	s := newScenario(t)
	s.givenGcc()

	data := s.givenDir("data")
	data.file("file.txt", "content")

	cSource := filepath.Join(s.tmpDir, "fchdir_access.c")
	cBinary := filepath.Join(s.tmpDir, "fchdir_access")
	createFile(t, cSource, `
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
`)
	//nolint:gosec // G204: test code with controlled args
	cmd := exec.CommandContext(context.Background(), "gcc", "-o", cBinary, cSource)
	require.NoError(t, cmd.Run())

	s.givenRules("fs:ro:" + testDir(s.tmpDir).String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, cBinary, data.String())

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK")
}

func Test_MonitoringAccess_ForkedChildDoesNotInheritParentCwdTracking(t *testing.T) {
	// A process forked from a parent with a tracked cwd starts with no tracked cwd of its
	// own. Its bare-path syscalls are UNKNOWN until it establishes its own cwd via
	// AT_FDCWD annotation, chdir, or fchdir. This is security-relevant: a child must not
	// silently inherit the parent's cwd and thereby resolve paths against the wrong root.
	requireAMD64(t)

	s := newScenario(t)
	s.givenGcc()

	// Static child binary: first syscall is access("child-relative.txt") via inline assembly.
	// No dynamic linker means no cwd-establishing AT_FDCWD annotation for this new pid.
	childSrc := filepath.Join(s.tmpDir, "child_bare.c")
	childBin := filepath.Join(s.tmpDir, "child_bare")
	createFile(t, childSrc, `
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
`)
	//nolint:gosec // G204: test code with controlled args
	childCmd := exec.CommandContext(context.Background(), "gcc", "-nostdlib", "-static", "-o", childBin, childSrc)
	require.NoError(t, childCmd.Run())

	// Dynamic wrapper: uses dynamic linker (establishes cwd tracking for its pid via
	// AT_FDCWD annotations), then fork+execs the static child. The child gets a new
	// pid with no tracked cwd of its own.
	wrapperSrc := filepath.Join(s.tmpDir, "fork_exec.c")
	wrapperBin := filepath.Join(s.tmpDir, "fork_exec")
	createFile(t, wrapperSrc, `
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
`)
	//nolint:gosec // G204: test code with controlled args
	wrapperCmd := exec.CommandContext(context.Background(), "gcc", "-o", wrapperBin, wrapperSrc)
	require.NoError(t, wrapperCmd.Run())

	s.givenRules("fs:ro:" + testDir(s.tmpDir).String())

	s.whenRunTextLog("", wrapperBin, childBin)

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", "child-relative.txt", "UNKNOWN", "unresolved-relative-path")
}

func Test_MonitoringAccess_BwrapSetupOperationsFilteredFromAccessLog(t *testing.T) {
	// Filesystem operations performed by bwrap during sandbox setup are filtered from the
	// access log; only accesses after the user command's execve appear in the log.
	s := newScenario(t)
	data := s.givenDir("data")
	filePath := data.file("file.txt", "hello")
	s.givenRules("fs:ro:" + data.String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

	s.thenExitCode(0)
	// Bwrap setup operations (newroot, oldroot) must not appear in the log.
	s.thenStderrNotContains("newroot")
	s.thenStderrNotContains("oldroot")
	// User command's file access must appear.
	s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK")
}

func Test_MonitoringAccess_ManagedPathAccessesFilteredFromAccessLog(t *testing.T) {
	// Accesses to managed paths (/proc, /dev, /tmp) are filtered from the access log
	// to avoid noise. Both reads (e.g. /proc/self/status) and writes (e.g. /dev/tty)
	// are filtered. Non-managed accesses still appear.

	t.Run("reads and writes to managed paths not logged", func(t *testing.T) {
		// given a sandbox that reads /proc and writes /dev (which all commands do)
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "hello")
		s.givenRules("fs:ro:" + data.String())

		// when running with --show-allowed so all results are visible
		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

		// then managed path accesses are filtered
		s.thenExitCode(0)
		s.thenStderrNotContains("/proc")
		s.thenStderrNotContains("/dev")
		s.thenStderrNotContains("/tmp")
	})

	t.Run("non-managed accesses still logged", func(t *testing.T) {
		// given a sandbox with a user directory
		s := newScenario(t)
		data := s.givenDir("data")
		filePath := data.file("file.txt", "hello")
		s.givenRules("fs:ro:" + data.String())

		// when running with --show-allowed
		s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", filePath)

		// then the user file access is logged
		s.thenExitCode(0)
		s.thenStderrHasEntry("READ", data.rel("file.txt"), "OK")
	})
}
