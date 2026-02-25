package logfilter

import (
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsNolog_FSRead_NilResolver_ReturnsFalse(t *testing.T) {
	entry := accesslog.Entry{Operation: accesslog.OperationRead, Target: "/home/user/project/cache", Result: accesslog.ResultOK, Rule: "fs:ro:/home/user"}
	assert.False(t, IsNolog(entry, nil, nil, nil))
}

func TestIsNolog_FSWrite_NilResolver_ReturnsFalse(t *testing.T) {
	entry := accesslog.Entry{Operation: accesslog.OperationWrite, Target: "/home/user/out.txt", Result: accesslog.ResultOK, Rule: "fs:rw:/home/user"}
	assert.False(t, IsNolog(entry, nil, nil, nil))
}

func TestIsNolog_FSRead_VisibleEntry_ReturnsFalse(t *testing.T) {
	resolver := fsrules.NewLogResolver([]fsrules.LogRule{
		{Visible: true, Path: "/home/user/project", RawRule: "fs:log:/home/user/project"},
	})
	entry := accesslog.Entry{Operation: accesslog.OperationRead, Target: "/home/user/project/main.go", Result: accesslog.ResultOK, Rule: "fs:ro:/home/user"}
	assert.False(t, IsNolog(entry, resolver, nil, nil))
}

func TestIsNolog_FSRead_NologEntry_ReturnsTrue(t *testing.T) {
	resolver := fsrules.NewLogResolver([]fsrules.LogRule{
		{Visible: false, Path: "/home/user/project/cache", RawRule: "fs:nolog:/home/user/project/cache"},
	})
	entry := accesslog.Entry{Operation: accesslog.OperationRead, Target: "/home/user/project/cache/data.bin", Result: accesslog.ResultOK, Rule: "fs:ro:/home/user"}
	assert.True(t, IsNolog(entry, resolver, nil, nil))
}

func TestIsNolog_HTTP_NilResolver_ReturnsFalse(t *testing.T) {
	entry := accesslog.Entry{Operation: accesslog.OperationHTTP, Target: "api.example.com:443", Result: accesslog.ResultOK, Rule: "net:http:api.example.com:443"}
	assert.False(t, IsNolog(entry, nil, nil, nil))
}

func TestIsNolog_HTTP_VisibleEntry_ReturnsFalse(t *testing.T) {
	rules := parseNetLogRules(t, []string{"log:api.example.com:443"})
	resolver := netrules.NewLogResolver(rules)
	entry := accesslog.Entry{Operation: accesslog.OperationHTTP, Target: "api.example.com:443", Result: accesslog.ResultOK, Rule: "net:http:api.example.com:443"}
	assert.False(t, IsNolog(entry, nil, resolver, nil))
}

func TestIsNolog_HTTP_NologEntry_ReturnsTrue(t *testing.T) {
	rules := parseNetLogRules(t, []string{"nolog:api.example.com:443"})
	resolver := netrules.NewLogResolver(rules)
	entry := accesslog.Entry{Operation: accesslog.OperationHTTP, Target: "api.example.com:443", Result: accesslog.ResultOK, Rule: "net:http:api.example.com:443"}
	assert.True(t, IsNolog(entry, nil, resolver, nil))
}

func TestIsNolog_HTTP_MalformedTarget_ReturnsFalse(t *testing.T) {
	rules := parseNetLogRules(t, []string{"nolog:api.example.com:443"})
	resolver := netrules.NewLogResolver(rules)
	// Target with no port
	entry := accesslog.Entry{Operation: accesslog.OperationHTTP, Target: "api.example.com", Result: accesslog.ResultOK, Rule: "net:http:api.example.com:443"}
	assert.False(t, IsNolog(entry, nil, resolver, nil))
}

func TestIsNolog_Syscall_MatchingNologRule_ReturnsTrue(t *testing.T) {
	entry := accesslog.Entry{Operation: accesslog.OperationSyscall, Target: "ptrace", Result: accesslog.ResultDeny, Rule: accesslog.RuleNoMatch}
	assert.True(t, IsNolog(entry, nil, nil, map[string]bool{"ptrace": true}))
}

func TestIsNolog_Syscall_NoMatchingNologRule_ReturnsFalse(t *testing.T) {
	entry := accesslog.Entry{Operation: accesslog.OperationSyscall, Target: "ptrace", Result: accesslog.ResultDeny, Rule: accesslog.RuleNoMatch}
	assert.False(t, IsNolog(entry, nil, nil, map[string]bool{"bpf": true}))
}

func TestIsNolog_Syscall_NilSyscallNolog_ReturnsFalse(t *testing.T) {
	entry := accesslog.Entry{Operation: accesslog.OperationSyscall, Target: "ptrace", Result: accesslog.ResultDeny, Rule: accesslog.RuleNoMatch}
	assert.False(t, IsNolog(entry, nil, nil, nil))
}

func TestIsNolog_UnexpectedOperation_Panics(t *testing.T) {
	entry := accesslog.Entry{Operation: "UNKNOWN_OP", Target: "/some/path", Result: accesslog.ResultOK, Rule: ""}
	assert.Panics(t, func() {
		IsNolog(entry, nil, nil, nil)
	})
}

// parseNetLogRules is a helper that parses net log rule bodies for testing.
// Each element should be in "visibility:target:port" format (without "net:" prefix).
func parseNetLogRules(t *testing.T, rules []string) []netrules.LogRule {
	t.Helper()
	var result []netrules.LogRule
	for _, r := range rules {
		rule, err := netrules.ParseLogRule(r)
		require.NoError(t, err)
		result = append(result, rule)
	}
	return result
}
