package syscallrules

import (
	"sort"
	"testing"

	"github.com/nonpop/execave/internal/seccomp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_AllowedSyscall(t *testing.T) {
	r := newTestResolver(t, "allow:ptrace")

	result := r.CheckAccess("ptrace")

	assert.True(t, result.Known)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Rule)
}

func TestResolve_BlockedSyscallNotInRules(t *testing.T) {
	r := newTestResolver(t, "allow:ptrace")

	result := r.CheckAccess("read")

	assert.False(t, result.Known)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
}

func TestResolve_EmptyRulesRuleableSyscallBlocked(t *testing.T) {
	r := NewResolver(nil, seccomp.RuleableSyscallNames())

	result := r.CheckAccess("ptrace")

	assert.True(t, result.Known)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
}

func TestResolve_EmptyRulesNonRuleableSyscallUnknown(t *testing.T) {
	r := NewResolver(nil, seccomp.RuleableSyscallNames())

	result := r.CheckAccess("read")

	assert.False(t, result.Known)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
}

func TestResolve_ResultContainsRawRule(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "")
	require.NoError(t, err)
	r := NewResolver([]Rule{rule}, seccomp.RuleableSyscallNames())

	result := r.CheckAccess("ptrace")

	require.NotNil(t, result.Rule)
	assert.Equal(t, "allow:ptrace", *result.Rule)
}

func TestResolve_MultipleRulesMatchesCorrectOne(t *testing.T) {
	r := newTestResolver(t, "allow:ptrace", "allow:process_vm_readv")

	result := r.CheckAccess("process_vm_readv")

	assert.True(t, result.Known)
	assert.True(t, result.Allowed)
}

func TestResolve_Names_AllRuleableSorted(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "")
	require.NoError(t, err)
	r := NewResolver([]Rule{rule}, seccomp.RuleableSyscallNames())

	names := r.Names()

	expected := seccomp.RuleableSyscallNames()
	sort.Strings(expected)
	assert.Equal(t, expected, names)
}

func TestResolve_AllowedNames_OnlyAllowRules(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "")
	require.NoError(t, err)
	r := NewResolver([]Rule{rule}, seccomp.RuleableSyscallNames())

	names := r.AllowedNames()

	assert.Equal(t, []string{"ptrace"}, names)
}

// --- helpers ---

func newTestResolver(t *testing.T, ruleBodies ...string) *Resolver {
	t.Helper()
	rules := make([]Rule, 0, len(ruleBodies))
	for _, body := range ruleBodies {
		rule, err := ParseRule(body, "")
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return NewResolver(rules, seccomp.RuleableSyscallNames())
}
