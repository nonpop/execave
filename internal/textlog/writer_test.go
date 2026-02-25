package textlog

import (
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
)

func TestFormatEntry_DenyReadAbsPath_FormatsColumnsAndShortensPath(t *testing.T) {
	wtr := New(nil, "/home/user", "/home/user/project", false, false, nil, nil, nil)
	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/.ssh/id_rsa",
		Result:    accesslog.ResultDeny,
		Rule:      "no-matching-rule",
	}
	assert.Equal(t, "DENY    READ   ~/.ssh/id_rsa  (no-matching-rule)", wtr.formatEntry(entry))
}

func TestFormatEntry_OKWrite_FormatsColumnsAndShortensPath(t *testing.T) {
	wtr := New(nil, "/home/user", "/home/user/project", false, false, nil, nil, nil)
	entry := accesslog.Entry{
		Operation: accesslog.OperationWrite,
		Target:    "/home/user/project/out.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:~/project",
	}
	assert.Equal(t, "OK      WRITE  out.txt  (fs:rw:~/project)", wtr.formatEntry(entry))
}

func TestFormatEntry_HTTP_TargetNotShortened(t *testing.T) {
	wtr := New(nil, "/home/user", "/home/user/project", false, false, nil, nil, nil)
	entry := accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:api.example.com:443",
	}
	assert.Equal(t, "OK      HTTP   api.example.com:443  (net:http:api.example.com:443)", wtr.formatEntry(entry))
}

func TestFormatEntry_UnknownResult_FormatsCorrectly(t *testing.T) {
	wtr := New(nil, "", "", false, false, nil, nil, nil)
	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/relative/path",
		Result:    accesslog.ResultUnknown,
		Rule:      "unresolved-relative-path",
	}
	// /relative/path is absolute (starts with /), but homeDir and configDir are empty so no shortening
	assert.Equal(t, "UNKNOWN READ   /relative/path  (unresolved-relative-path)", wtr.formatEntry(entry))
}

func TestFormatEntry_EmptyHomeDirAndConfigDir_UsesAbsolutePath(t *testing.T) {
	wtr := New(nil, "", "", false, false, nil, nil, nil)
	entry := accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/cat",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}
	assert.Equal(t, "OK      READ   /usr/bin/cat  (fs:ro:/usr)", wtr.formatEntry(entry))
}
