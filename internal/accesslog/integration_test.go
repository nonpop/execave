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

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "/tmp/data/file.txt", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "fs:ro:/tmp/data", entries[0].Rule)
}

func TestIntegration_LogFormat_DeniedWriteLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/tmp/project/.git/config",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:ro:/tmp/project/.git",
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationWrite, entries[0].Operation)
	assert.Equal(t, "/tmp/project/.git/config", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, "fs:ro:/tmp/project/.git", entries[0].Rule)
}

func TestIntegration_LogFormat_NoAccessRuleLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/project/.env",
		Result:    accesslog.ResultDeny,
		Rule:      "fs:none:/tmp/project/.env",
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "/tmp/project/.env", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, "fs:none:/tmp/project/.env", entries[0].Rule)
}

func TestIntegration_LogFormat_NoMatchingRuleLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/secret",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "/tmp/secret", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}

func TestIntegration_LogFormat_UnresolvedRelativePathLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "foo/bar.txt",
		Result:    accesslog.ResultUnknown,
		Rule:      accesslog.RuleUnresolvedRelativePath,
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationRead, entries[0].Operation)
	assert.Equal(t, "foo/bar.txt", entries[0].Target)
	assert.Equal(t, accesslog.ResultUnknown, entries[0].Result)
	assert.Equal(t, accesslog.RuleUnresolvedRelativePath, entries[0].Rule)
}

func TestIntegration_LogFormat_AllowedHttpsRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTPS,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:https:api.example.com:443",
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTPS, entries[0].Operation)
	assert.Equal(t, "api.example.com:443", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "net:https:api.example.com:443", entries[0].Rule)
}

func TestIntegration_LogFormat_DeniedHttpsRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTPS,
		Target:    "malicious.example.com:443",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTPS, entries[0].Operation)
	assert.Equal(t, "malicious.example.com:443", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}

func TestIntegration_LogFormat_AllowedHttpRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:localhost:3000",
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTP, entries[0].Operation)
	assert.Equal(t, "localhost:3000", entries[0].Target)
	assert.Equal(t, accesslog.ResultOK, entries[0].Result)
	assert.Equal(t, "net:http:localhost:3000", entries[0].Rule)
}

func TestIntegration_LogFormat_DeniedHttpRequestLogged(t *testing.T) {
	logger := accesslog.New(nil)

	err := logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "localhost:3000",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})
	require.NoError(t, err)

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, accesslog.OperationHTTP, entries[0].Operation)
	assert.Equal(t, "localhost:3000", entries[0].Target)
	assert.Equal(t, accesslog.ResultDeny, entries[0].Result)
	assert.Equal(t, accesslog.RuleNoMatch, entries[0].Rule)
}
