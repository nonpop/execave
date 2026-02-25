package accesslog_test

import (
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Log format ---

func TestIntegration_LogFormat_AllowedReadLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "/tmp/data/file.txt", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "fs:ro:/tmp/data", entries[0].Rule)
}

func TestIntegration_LogFormat_DeniedWriteLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/.git/config",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:ro:/tmp/project/.git",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationWrite, entries[0].Operation)
	assert.Equal(t, "/tmp/project/.git/config", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, "fs:ro:/tmp/project/.git", entries[0].Rule)
}

func TestIntegration_LogFormat_NoAccessRuleLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/project/.env",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:none:/tmp/project/.env",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "/tmp/project/.env", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, "fs:none:/tmp/project/.env", entries[0].Rule)
}

func TestIntegration_LogFormat_NoMatchingRuleLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/secret",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "/tmp/secret", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}

func TestIntegration_LogFormat_UnresolvedRelativePathLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "foo/bar.txt",
		Result:    accesslog.ResultUnknown,
		Rule:      accesslog.RuleUnresolvedRelativePath,
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "foo/bar.txt", entries[0].Target)
	assert.Equal(t, accesslog.ResultUnknown, entries[0].Result)
	assert.Equal(t, accesslog.RuleUnresolvedRelativePath, entries[0].Rule)
}

func TestIntegration_LogFormat_AllowedHttpsRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:api.example.com:443",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTP, entries[0].Operation)
	assert.Equal(t, "api.example.com:443", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "net:http:api.example.com:443", entries[0].Rule)
}

func TestIntegration_LogFormat_DeniedHttpsRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "malicious.example.com:443",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTP, entries[0].Operation)
	assert.Equal(t, "malicious.example.com:443", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}

func TestIntegration_LogFormat_AllowedHttpRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:localhost:3000",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTP, entries[0].Operation)
	assert.Equal(t, "localhost:3000", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "net:http:localhost:3000", entries[0].Rule)
}

func TestIntegration_LogFormat_DeniedHttpRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTP, entries[0].Operation)
	assert.Equal(t, "localhost:3000", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}

// --- Requirement: Log format (SYSCALL) ---

func TestIntegration_LogFormat_SeccompDeniedSyscallLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "bpf",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationSyscall, entries[0].Operation)
	assert.Equal(t, "bpf", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}

func TestIntegration_LogFormat_AllowedSyscallLogged(t *testing.T) {
	logger := accesslog.New(nil)

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "bpf",
		Result:    accesslog.ResultOK,
		Rule:      "syscall:allow:bpf",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationSyscall, entries[0].Operation)
	assert.Equal(t, "bpf", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "syscall:allow:bpf", entries[0].Rule)
}

func TestIntegration_LogFormat_SyscallEntriesDeduplicated(t *testing.T) {
	logger := accesslog.New(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "bpf",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	}
	logger.Log(entry)
	logger.Log(entry)

	assert.Len(t, logger.Entries(), 1)
}

func TestIntegration_LogFormat_SyscallEntriesNotFilteredByManagedPaths(t *testing.T) {
	logger := accesslog.New([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationSyscall,
		Target:    "mount",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "mount", entries[0].Target)
}

// --- Requirement: Log deduplication ---

func TestIntegration_LogDeduplication_RepeatedReadsDeduplicated(t *testing.T) {
	logger := accesslog.New(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	}
	logger.Log(entry)
	logger.Log(entry)
	logger.Log(entry)

	assert.Len(t, logger.Entries(), 1)
}

func TestIntegration_LogDeduplication_ReadAndWriteBothLogged(t *testing.T) {
	logger := accesslog.New(nil)

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

	assert.Len(t, logger.Entries(), 2)
}

func TestIntegration_LogDeduplication_RepeatedHttpsRequestsDeduplicated(t *testing.T) {
	logger := accesslog.New(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:api.example.com:443",
	}
	logger.Log(entry)
	logger.Log(entry)
	logger.Log(entry)

	assert.Len(t, logger.Entries(), 1)
}

func TestIntegration_LogDeduplication_RepeatedWritesDeduplicated(t *testing.T) {
	logger := accesslog.New(nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/output.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/tmp/project",
	}
	logger.Log(entry)
	logger.Log(entry)
	logger.Log(entry)

	assert.Len(t, logger.Entries(), 1)
}

// --- Requirement: Infrastructure path filtering ---

func TestIntegration_InfrastructurePathFiltering_InfrastructurePathsNotLogged(t *testing.T) {
	logger := accesslog.New([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/proc/self/status",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/proc",
	})

	assert.Empty(t, logger.Entries())
}

func TestIntegration_InfrastructurePathFiltering_InfrastructureWritesNotLogged(t *testing.T) {
	logger := accesslog.New([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/dev/tty",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/dev",
	})

	assert.Empty(t, logger.Entries())
}

func TestIntegration_InfrastructurePathFiltering_NonInfrastructurePathsStillLogged(t *testing.T) {
	logger := accesslog.New([]string{"/dev", "/proc", "/tmp"})

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/bash",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "/usr/bin/bash", entries[0].Target)
}
