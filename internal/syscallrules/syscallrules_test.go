package syscallrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Parse: valid rules ---

func TestParse_ValidAllow(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "/etc/execave.json")
	require.NoError(t, err)

	assert.Equal(t, actionAllow, rule.action)
	assert.Equal(t, "ptrace", rule.Name)
	assert.Equal(t, "/etc/execave.json", rule.SourcePath)
	assert.Equal(t, "allow:ptrace", rule.RawRule)
}

func TestParse_SourcePathStoredOnRule(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "/some/config.json")
	require.NoError(t, err)

	assert.Equal(t, "/some/config.json", rule.SourcePath)
}

func TestParse_EmptySourcePath(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "")
	require.NoError(t, err)

	assert.Equal(t, "", rule.SourcePath)
}

// --- Parse: invalid rules ---

func TestParse_MissingColon(t *testing.T) {
	_, err := ParseRule("allow", "")
	assert.ErrorContains(t, err, "malformed syscall rule")
}

func TestParse_EmptyName(t *testing.T) {
	_, err := ParseRule("allow:", "")
	assert.ErrorContains(t, err, "malformed syscall rule")
}

func TestParse_UnknownAction(t *testing.T) {
	_, err := ParseRule("deny:ptrace", "")
	assert.ErrorContains(t, err, "unknown syscall action")
}

func TestParse_EmptyInput(t *testing.T) {
	_, err := ParseRule("", "")
	assert.ErrorContains(t, err, "malformed syscall rule")
}

// --- Identity ---

func TestIdentity_AllowRule(t *testing.T) {
	rule, err := ParseRule("allow:ptrace", "")
	require.NoError(t, err)

	assert.Equal(t, "allow:ptrace", rule.Canonical())
}

func TestCanonicalRoundTrip(t *testing.T) {
	cases := []string{
		"allow:ptrace",
		"allow:bpf",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			rule1, err := ParseRule(tc, "")
			require.NoError(t, err)
			canonical1 := rule1.Canonical()

			rule2, err := ParseRule(canonical1, "")
			require.NoError(t, err)
			canonical2 := rule2.Canonical()

			assert.Equal(t, canonical1, canonical2)
		})
	}
}

// --- Validate ---

func TestValidate_ValidRule(t *testing.T) {
	rules := []Rule{makeRule(t, "allow:ptrace")}
	err := ValidateRules(rules)
	assert.NoError(t, err)
}

func TestValidate_EmptyRules(t *testing.T) {
	err := ValidateRules(nil)
	assert.NoError(t, err)
}

func TestValidate_NonRuleableName(t *testing.T) {
	rules := []Rule{makeRule(t, "allow:read")}
	err := ValidateRules(rules)
	assert.ErrorContains(t, err, "invalid syscall:allow target")
}

func TestValidate_DuplicateAllow(t *testing.T) {
	rules := []Rule{
		makeRule(t, "allow:ptrace"),
		makeRule(t, "allow:ptrace"),
	}
	err := ValidateRules(rules)
	assert.ErrorContains(t, err, "duplicate syscall allow rule")
}

func TestValidate_MultipleRulesNoDuplicates(t *testing.T) {
	rules := []Rule{
		makeRule(t, "allow:ptrace"),
		makeRule(t, "allow:bpf"),
	}
	err := ValidateRules(rules)
	assert.NoError(t, err)
}

// --- helpers ---

func makeRule(t *testing.T, ruleBody string) Rule {
	t.Helper()
	rule, err := ParseRule(ruleBody, "")
	require.NoError(t, err)
	return rule
}
