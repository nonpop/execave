package syscallrules_test

import (
	"sort"
	"testing"

	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/syscallrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Syscall rule syntax ---

func TestIntegration_SyscallRuleSyntax_ValidAllowRule(t *testing.T) {
	_, err := syscallrules.ParseRule("allow:ptrace", "")

	assert.NoError(t, err)
}

func TestIntegration_SyscallRuleSyntax_InvalidAction(t *testing.T) {
	_, err := syscallrules.ParseRule("deny:ptrace", "")

	assert.ErrorContains(t, err, "unknown syscall action")
}

func TestIntegration_SyscallRuleSyntax_MissingName(t *testing.T) {
	_, err := syscallrules.ParseRule("allow:", "")

	assert.ErrorContains(t, err, "malformed syscall rule")
}

func TestIntegration_SyscallRuleSyntax_MissingColon(t *testing.T) {
	_, err := syscallrules.ParseRule("allow", "")

	assert.ErrorContains(t, err, "malformed syscall rule")
}

// --- Requirement: Validation ---

func TestIntegration_Validation_ValidRulesAccepted(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRule(t, "allow:ptrace"),
	}

	err := syscallrules.ValidateRules(rules)

	assert.NoError(t, err)
}

func TestIntegration_Validation_NonRuleableNameRejected(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRule(t, "allow:read"),
	}

	err := syscallrules.ValidateRules(rules)

	assert.ErrorContains(t, err, "invalid syscall:allow target")
}

func TestIntegration_Validation_DuplicateAllowRuleRejected(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRule(t, "allow:ptrace"),
		parseSyscallRule(t, "allow:ptrace"),
	}

	err := syscallrules.ValidateRules(rules)

	assert.ErrorContains(t, err, "duplicate syscall allow rule")
}

func TestIntegration_Validation_EmptyRulesAccepted(t *testing.T) {
	err := syscallrules.ValidateRules(nil)

	assert.NoError(t, err)
}

// --- Requirement: Resolution ---

func TestIntegration_Resolution_AllowedSyscallReturnsAllowed(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRuleWithRaw(t, "allow:ptrace", "syscall:allow:ptrace"),
	}
	resolver := syscallrules.NewResolver(rules, seccomp.RuleableSyscallNames())

	result := resolver.CheckAccess("ptrace")

	assert.True(t, result.Known)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "syscall:allow:ptrace", *result.Rule)
}

func TestIntegration_Resolution_UnknownSyscallDefaultDeny(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRule(t, "allow:ptrace"),
	}
	resolver := syscallrules.NewResolver(rules, seccomp.RuleableSyscallNames())

	result := resolver.CheckAccess("read")

	assert.False(t, result.Known)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
}

func TestIntegration_Resolution_EmptyRulesRuleableSyscallBlocked(t *testing.T) {
	resolver := syscallrules.NewResolver(nil, seccomp.RuleableSyscallNames())

	result := resolver.CheckAccess("ptrace")

	assert.True(t, result.Known)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
}

func TestIntegration_Resolution_Names_AllRuleableSorted(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRule(t, "allow:ptrace"),
	}
	resolver := syscallrules.NewResolver(rules, seccomp.RuleableSyscallNames())

	names := resolver.Names()

	expected := seccomp.RuleableSyscallNames()
	sort.Strings(expected)
	assert.Equal(t, expected, names)
}

func TestIntegration_Resolution_AllowedNames(t *testing.T) {
	rules := []syscallrules.Rule{
		parseSyscallRule(t, "allow:ptrace"),
		parseSyscallRule(t, "allow:bpf"),
	}
	resolver := syscallrules.NewResolver(rules, seccomp.RuleableSyscallNames())

	names := resolver.AllowedNames()

	assert.Equal(t, []string{"bpf", "ptrace"}, names)
}

// --- helpers ---

func parseSyscallRule(t *testing.T, ruleBody string) syscallrules.Rule {
	t.Helper()
	rule, err := syscallrules.ParseRule(ruleBody, "")
	require.NoError(t, err)
	return rule
}

func parseSyscallRuleWithRaw(t *testing.T, ruleBody, rawRule string) syscallrules.Rule {
	t.Helper()
	rule, err := syscallrules.ParseRule(ruleBody, "")
	require.NoError(t, err)
	rule.RawRule = rawRule
	return rule
}
