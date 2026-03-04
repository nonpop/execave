package accesslog_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countLogLines returns the number of log entries written to s.
func countLogLines(s string) int {
	return strings.Count(s, "\n")
}

// newLoggerWithBuf creates a Logger that writes all entries to a buffer.
func newLoggerWithBuf(managedPaths []string) (*accesslog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	cfg := &accesslog.Config{ManagedPaths: managedPaths, ShowAllowed: true}
	return accesslog.New(&buf, cfg), &buf
}

// --- Requirement: Log format ---

func TestIntegration_LogFormat_AllowedReadLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
	assert.Contains(t, buf.String(), "/tmp/data/file.txt")
	assert.Contains(t, buf.String(), "OK")
	assert.Contains(t, buf.String(), "fs:ro:/tmp/data")
}

func TestIntegration_LogFormat_DeniedWriteLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/.git/config",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:ro:/tmp/project/.git",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "WRITE")
	assert.Contains(t, buf.String(), "/tmp/project/.git/config")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), "fs:ro:/tmp/project/.git")
}

func TestIntegration_LogFormat_NoAccessRuleLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/project/.env",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:none:/tmp/project/.env",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
	assert.Contains(t, buf.String(), "/tmp/project/.env")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), "fs:none:/tmp/project/.env")
}

func TestIntegration_LogFormat_NoMatchingRuleLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/secret",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
	assert.Contains(t, buf.String(), "/tmp/secret")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), accesslog.RuleNoMatch)
}

func TestIntegration_LogFormat_UnresolvedRelativePathLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "foo/bar.txt",
		Result:    accesslog.ResultUnknown,
		Rule:      accesslog.RuleUnresolvedRelativePath,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "READ")
	assert.Contains(t, buf.String(), "foo/bar.txt")
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), accesslog.RuleUnresolvedRelativePath)
}

func TestIntegration_LogFormat_AllowedHttpsRequestLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:api.example.com:443",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "HTTP")
	assert.Contains(t, buf.String(), "api.example.com:443")
	assert.Contains(t, buf.String(), "OK")
	assert.Contains(t, buf.String(), "net:http:api.example.com:443")
}

func TestIntegration_LogFormat_DeniedHttpsRequestLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "malicious.example.com:443",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "HTTP")
	assert.Contains(t, buf.String(), "malicious.example.com:443")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), accesslog.RuleNoMatch)
}

func TestIntegration_LogFormat_AllowedHttpRequestLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:localhost:3000",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "HTTP")
	assert.Contains(t, buf.String(), "localhost:3000")
	assert.Contains(t, buf.String(), "OK")
	assert.Contains(t, buf.String(), "net:http:localhost:3000")
}

func TestIntegration_LogFormat_DeniedHttpRequestLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "HTTP")
	assert.Contains(t, buf.String(), "localhost:3000")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), accesslog.RuleNoMatch)
}

// --- Requirement: Log format (SYSCALL) ---

func TestIntegration_LogFormat_SeccompDeniedSyscallLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "bpf",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "SYSCALL")
	assert.Contains(t, buf.String(), "bpf")
	assert.Contains(t, buf.String(), "DENY")
	assert.Contains(t, buf.String(), accesslog.RuleNoMatch)
}

func TestIntegration_LogFormat_AllowedSyscallLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "bpf",
		Result:    accesslog.ResultOK,
		Rule:      "syscall:allow:bpf",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "SYSCALL")
	assert.Contains(t, buf.String(), "bpf")
	assert.Contains(t, buf.String(), "OK")
	assert.Contains(t, buf.String(), "syscall:allow:bpf")
}

func TestIntegration_LogFormat_SyscallEntriesDeduplicated(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "bpf",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	}
	logger.Log(entry)
	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestIntegration_LogFormat_SyscallEntriesNotFilteredByManagedPaths(t *testing.T) {
	logger, buf := newLoggerWithBuf([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "mount",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "mount")
}

// --- Requirement: Log deduplication ---

func TestIntegration_LogDeduplication_RepeatedReadsDeduplicated(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	}
	logger.Log(entry)
	logger.Log(entry)
	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestIntegration_LogDeduplication_ReadAndWriteBothLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	})
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/tmp/data",
	})

	assert.Equal(t, 2, countLogLines(buf.String()))
}

func TestIntegration_LogDeduplication_RepeatedHttpsRequestsDeduplicated(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:api.example.com:443",
	}
	logger.Log(entry)
	logger.Log(entry)
	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

func TestIntegration_LogDeduplication_RepeatedWritesDeduplicated(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/output.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/tmp/project",
	}
	logger.Log(entry)
	logger.Log(entry)
	logger.Log(entry)

	assert.Equal(t, 1, countLogLines(buf.String()))
}

// --- Requirement: Infrastructure path filtering ---

func TestIntegration_InfrastructurePathFiltering_InfrastructurePathsNotLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/proc/self/status",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/proc",
	})

	assert.Empty(t, buf.String())
}

func TestIntegration_InfrastructurePathFiltering_InfrastructureWritesNotLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/dev/tty",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/dev",
	})

	assert.Empty(t, buf.String())
}

func TestIntegration_InfrastructurePathFiltering_NonInfrastructurePathsStillLogged(t *testing.T) {
	logger, buf := newLoggerWithBuf([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/bash",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), "/usr/bin/bash")
}

// --- Requirement: Unenforced mode ---

func TestIntegration_UnenforcedMode_ResultUnenforcedLoggedDirectly(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/file.txt",
		Result:    accesslog.ResultUnenforced,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), string(accesslog.ResultUnenforced))
}

func TestIntegration_NormalMode_ResultPreserved(t *testing.T) {
	logger, buf := newLoggerWithBuf(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/file.txt",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	assert.Equal(t, 1, countLogLines(buf.String()))
	assert.Contains(t, buf.String(), string(accesslog.ResultDeny))
}

// --- Requirement: Text log output (Config) ---

// runLoggerWithBuf creates a Logger with an Out buffer, logs all entries, calls Close,
// and returns the buffer contents as a string.
func runLoggerWithBuf(t *testing.T, showAllowed bool, entries []accesslog.Entry) string {
	t.Helper()
	var buf bytes.Buffer
	cfg := &accesslog.Config{
		HomeDir:     "/home/user",
		ConfigDir:   "/home/user/project",
		ShowAllowed: showAllowed,
	}
	logger := accesslog.New(&buf, cfg)
	for _, e := range entries {
		logger.Log(e)
	}
	require.NoError(t, logger.Close())
	return buf.String()
}

func TestIntegration_TextLog_OKEntriesHiddenByDefault(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/usr/bin/cat", Result: accesslog.ResultOK, Rule: "fs:ro:/usr"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runLoggerWithBuf(t, false, entries)

	assert.NotContains(t, out, "/usr/bin/cat")
	assert.Contains(t, out, "/etc/secret")
}

func TestIntegration_TextLog_OKEntriesShownWithShowAllowed(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/usr/bin/cat", Result: accesslog.ResultOK, Rule: "fs:ro:/usr"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runLoggerWithBuf(t, true, entries)

	assert.Contains(t, out, "/usr/bin/cat")
	assert.Contains(t, out, "/etc/secret")
}

func TestIntegration_TextLog_PathShorteningApplied(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/home/user/.ssh/id_rsa", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
		{Operation: accesslog.OperationRead, Target: "/home/user/project/src/main.go", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runLoggerWithBuf(t, false, entries)

	assert.Contains(t, out, "~/.ssh/id_rsa")
	assert.Contains(t, out, "src/main.go")
	assert.NotContains(t, out, "/home/user/.ssh/id_rsa")
	assert.NotContains(t, out, "/home/user/project/src/main.go")
}

func TestIntegration_TextLog_EntriesWrittenImmediatelyOnLog(t *testing.T) {
	var buf bytes.Buffer
	cfg := &accesslog.Config{ShowAllowed: true}
	logger := accesslog.New(&buf, cfg)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/etc/hosts",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/etc",
	})

	// Entry is written immediately — no flush step needed.
	assert.Contains(t, buf.String(), "/etc/hosts")
	require.NoError(t, logger.Close())
}

func TestIntegration_TextLog_OutputFormatContainsAllColumns(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runLoggerWithBuf(t, false, entries)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 1)
	// Output line contains result, operation, path, rule
	assert.Contains(t, lines[0], "DENY")
	assert.Contains(t, lines[0], "READ")
	assert.Contains(t, lines[0], "/etc/secret")
	assert.Contains(t, lines[0], "(no-matching-rule)")
}

// --- UNENFORCED result handling ---

func TestIntegration_TextLog_UnenforcedEntryFormattedCorrectly(t *testing.T) {
	var buf bytes.Buffer
	cfg := &accesslog.Config{
		HomeDir:   "/home/user",
		ConfigDir: "/home/user/project",
	}
	logger := accesslog.New(&buf, cfg)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/.ssh/id_rsa",
		Result:    accesslog.ResultUnenforced,
		Rule:      accesslog.RuleNoMatch,
	})

	require.NoError(t, logger.Close())
	out := buf.String()
	assert.Contains(t, out, "UNENFORCED")
	assert.Contains(t, out, "READ")
	assert.Contains(t, out, "~/.ssh/id_rsa")
}

func TestIntegration_TextLog_UnenforcedEntryShownWhenShowAllowedFalse(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/usr/bin/cat", Result: accesslog.ResultUnenforced, Rule: "fs:ro:/usr"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultUnenforced, Rule: accesslog.RuleNoMatch},
		{Operation: accesslog.OperationRead, Target: "/home/user/file.txt", Result: accesslog.ResultUnenforced, Rule: accesslog.RuleNoMatch},
	}

	// Logger with ShowAllowed=false: UNENFORCED entries must still appear.
	var buf bytes.Buffer
	cfg := &accesslog.Config{
		HomeDir:   "/home/user",
		ConfigDir: "/home/user/project",
	}
	logger := accesslog.New(&buf, cfg)

	for _, e := range entries {
		logger.Log(e)
	}

	require.NoError(t, logger.Close())
	out := buf.String()
	// All three UNENFORCED entries must appear even with showAllowed=false.
	assert.Contains(t, out, "/usr/bin/cat")
	assert.Contains(t, out, "/etc/secret")
	assert.Contains(t, out, "file.txt")
	assert.NotContains(t, out, string(accesslog.ResultOK))
	assert.NotContains(t, out, string(accesslog.ResultDeny))
}
