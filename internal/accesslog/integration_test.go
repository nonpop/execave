package accesslog_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Log format ---

func TestIntegration_LogFormat_AllowedReadLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "READ", fields[0])
	assert.Equal(t, "/tmp/data/file.txt", fields[1])
	assert.Equal(t, "OK", fields[2])
	assert.Equal(t, "fs:ro:/tmp/data", fields[3])
}

func TestIntegration_LogFormat_DeniedWriteLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/.git/config",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:ro:/tmp/project/.git",
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "WRITE", fields[0])
	assert.Equal(t, "/tmp/project/.git/config", fields[1])
	assert.Equal(t, "DENY", fields[2])
	assert.Equal(t, "fs:ro:/tmp/project/.git", fields[3])
}

func TestIntegration_LogFormat_NoAccessRuleLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/project/.env",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:none:/tmp/project/.env",
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "READ", fields[0])
	assert.Equal(t, "/tmp/project/.env", fields[1])
	assert.Equal(t, "DENY", fields[2])
	assert.Equal(t, "fs:none:/tmp/project/.env", fields[3])
}

func TestIntegration_LogFormat_NoMatchingRuleLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/secret",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "READ", fields[0])
	assert.Equal(t, "/tmp/secret", fields[1])
	assert.Equal(t, "DENY", fields[2])
	assert.Equal(t, "no-matching-rule", fields[3])
}

func TestIntegration_LogFormat_UnresolvedRelativePathLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "foo/bar.txt",
		Result:    accesslog.ResultUnknown,
		Rule:      accesslog.RuleUnresolvedRelativePath,
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "READ", fields[0])
	assert.Equal(t, "foo/bar.txt", fields[1])
	assert.Equal(t, "UNKNOWN", fields[2])
	assert.Equal(t, "unresolved-relative-path", fields[3])
}

func TestIntegration_LogFormat_AllowedHttpsRequestLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTPS,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:https:api.example.com:443",
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "HTTPS", fields[0])
	assert.Equal(t, "api.example.com:443", fields[1])
	assert.Equal(t, "OK", fields[2])
	assert.Equal(t, "net:https:api.example.com:443", fields[3])
}

func TestIntegration_LogFormat_DeniedHttpsRequestLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTPS,
		Target:    "malicious.example.com:443",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "HTTPS", fields[0])
	assert.Equal(t, "malicious.example.com:443", fields[1])
	assert.Equal(t, "DENY", fields[2])
	assert.Equal(t, "no-matching-rule", fields[3])
}

func TestIntegration_LogFormat_AllowedHttpRequestLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:localhost:3000",
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "HTTP", fields[0])
	assert.Equal(t, "localhost:3000", fields[1])
	assert.Equal(t, "OK", fields[2])
	assert.Equal(t, "net:http:localhost:3000", fields[3])
}

func TestIntegration_LogFormat_DeniedHttpRequestLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})
	require.NoError(t, err)

	line := strings.TrimSpace(buf.String())
	fields := strings.Fields(line)
	require.Len(t, fields, 4)
	assert.Equal(t, "HTTP", fields[0])
	assert.Equal(t, "localhost:3000", fields[1])
	assert.Equal(t, "DENY", fields[2])
	assert.Equal(t, "no-matching-rule", fields[3])
}

// --- Requirement: Log deduplication ---

func TestIntegration_LogDeduplication_RepeatedReadsDeduplicated(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	}

	for range 3 {
		err := logger.Log(entry)
		require.NoError(t, err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 1)
}

func TestIntegration_LogDeduplication_ReadAndWriteBothLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/project/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/tmp/project",
	})
	require.NoError(t, err)

	err = logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/tmp/project",
	})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 2)
	assert.Contains(t, lines[0], "READ")
	assert.Contains(t, lines[1], "WRITE")
}

func TestIntegration_LogDeduplication_RepeatedHttpsRequestsDeduplicated(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationHTTPS,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:https:api.example.com:443",
	}

	for range 3 {
		err := logger.Log(entry)
		require.NoError(t, err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 1)
}

func TestIntegration_LogDeduplication_RepeatedWritesDeduplicated(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, nil)

	entry := accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/out.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/tmp/project",
	}

	for range 3 {
		err := logger.Log(entry)
		require.NoError(t, err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 1)
}

// --- Requirement: Infrastructure path filtering ---

func TestIntegration_InfrastructurePathFiltering_InfrastructurePathsNotLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, []string{"/dev", "/proc", "/tmp"})

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/proc/self/status",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/proc",
	})
	require.NoError(t, err)

	assert.Empty(t, buf.String())
}

func TestIntegration_InfrastructurePathFiltering_InfrastructureWritesNotLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, []string{"/dev", "/proc", "/tmp"})

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/dev/tty",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:/dev",
	})
	require.NoError(t, err)

	assert.Empty(t, buf.String())
}

func TestIntegration_InfrastructurePathFiltering_NonInfrastructurePathsStillLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := accesslog.New(&buf, []string{"/dev", "/proc", "/tmp"})

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/bash",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "/usr/bin/bash")
}
