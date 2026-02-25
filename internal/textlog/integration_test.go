package textlog_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/textlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runWriterWithBuf starts a Writer backed by a bytes.Buffer, logs entries, cancels,
// and returns the buffer contents as a string.
func runWriterWithBuf(t *testing.T, showAllowed, showNolog bool, fsRes *fsrules.LogResolver, entries []accesslog.Entry) string {
	t.Helper()
	var buf bytes.Buffer
	wtr := textlog.New(&buf, "/home/user", "/home/user/project", showAllowed, showNolog, fsRes, nil, nil)

	logger := accesslog.New(nil)
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- wtr.Run(ctx, logger)
	}()

	for _, e := range entries {
		logger.Log(e)
	}

	cancel()
	require.NoError(t, <-done)
	return buf.String()
}

func TestIntegration_TextLog_OKEntriesHiddenByDefault(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/usr/bin/cat", Result: accesslog.ResultOK, Rule: "fs:ro:/usr"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, false, false, nil, entries)

	assert.NotContains(t, out, "/usr/bin/cat")
	assert.Contains(t, out, "/etc/secret")
}

func TestIntegration_TextLog_OKEntriesShownWithShowAllowed(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/usr/bin/cat", Result: accesslog.ResultOK, Rule: "fs:ro:/usr"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, true, false, nil, entries)

	assert.Contains(t, out, "/usr/bin/cat")
	assert.Contains(t, out, "/etc/secret")
}

func TestIntegration_TextLog_NologEntriesHiddenByDefault(t *testing.T) {
	fsRes := fsrules.NewLogResolver([]fsrules.LogRule{
		{Visible: false, Path: "/home/user/project/cache", RawRule: "fs:nolog:/home/user/project/cache"},
	})
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/home/user/project/cache/data.bin", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, false, false, fsRes, entries)

	assert.NotContains(t, out, "cache/data.bin")
	assert.Contains(t, out, "/etc/secret")
}

func TestIntegration_TextLog_NologEntriesShownWithShowNolog(t *testing.T) {
	fsRes := fsrules.NewLogResolver([]fsrules.LogRule{
		{Visible: false, Path: "/home/user/project/cache", RawRule: "fs:nolog:/home/user/project/cache"},
	})
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/home/user/project/cache/data.bin", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, false, true, fsRes, entries)

	assert.Contains(t, out, "cache/data.bin")
}

func TestIntegration_TextLog_IndependentFilterAxes_ShowAllowedDoesNotEnableNolog(t *testing.T) {
	fsRes := fsrules.NewLogResolver([]fsrules.LogRule{
		{Visible: false, Path: "/home/user/project/cache", RawRule: "fs:nolog:/home/user/project/cache"},
	})
	entries := []accesslog.Entry{
		// OK entry that is also nolog — should appear when showAllowed but not showNolog
		{Operation: accesslog.OperationRead, Target: "/home/user/project/cache/data.bin", Result: accesslog.ResultOK, Rule: "fs:ro:~/project"},
		// OK entry that is not nolog — should appear when showAllowed
		{Operation: accesslog.OperationRead, Target: "/usr/bin/cat", Result: accesslog.ResultOK, Rule: "fs:ro:/usr"},
		// DENY entry that is not nolog — should always appear
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, true, false, fsRes, entries)

	// nolog+OK entry hidden even though showAllowed=true (nolog filter still applies)
	assert.NotContains(t, out, "cache/data.bin")
	// non-nolog OK entry visible
	assert.Contains(t, out, "/usr/bin/cat")
	// DENY visible
	assert.Contains(t, out, "/etc/secret")
}

func TestIntegration_TextLog_PathShorteningApplied(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/home/user/.ssh/id_rsa", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
		{Operation: accesslog.OperationRead, Target: "/home/user/project/src/main.go", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, false, false, nil, entries)

	assert.Contains(t, out, "~/.ssh/id_rsa")
	assert.Contains(t, out, "src/main.go")
	assert.NotContains(t, out, "/home/user/.ssh/id_rsa")
	assert.NotContains(t, out, "/home/user/project/src/main.go")
}

func TestIntegration_TextLog_FinalDrainOnContextCancellation(t *testing.T) {
	var buf bytes.Buffer
	wtr := textlog.New(&buf, "", "", true, false, nil, nil, nil)

	logger := accesslog.New(nil)
	ctx, cancel := context.WithCancel(t.Context())

	// Cancel before writing entries to verify final drain picks them up
	cancel()

	// Log entries and immediately check — the final drain happens during Run
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/etc/hosts",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/etc",
	})

	// Run should drain on cancel
	require.NoError(t, wtr.Run(ctx, logger))

	assert.Contains(t, buf.String(), "/etc/hosts")
}

func TestIntegration_TextLog_OutputFormatContainsAllColumns(t *testing.T) {
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: "no-matching-rule"},
	}
	out := runWriterWithBuf(t, false, false, nil, entries)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 1)
	// Output line contains result, operation, path, rule
	assert.Contains(t, lines[0], "DENY")
	assert.Contains(t, lines[0], "READ")
	assert.Contains(t, lines[0], "/etc/secret")
	assert.Contains(t, lines[0], "(no-matching-rule)")
}
