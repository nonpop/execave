package fsrules_test

import (
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func roRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Resource:   fsrules.ResourceFS,
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
	}
}

func rwRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Resource:   fsrules.ResourceFS,
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "rw:" + path,
	}
}

// --- Requirement: Rule syntax validation ---

func TestIntegration_RuleSyntaxValidation_InvalidPermissionType(t *testing.T) {
	_, err := fsrules.Parse("readonly:/path", "/")

	require.ErrorContains(t, err, "invalid permission type")
}

func TestIntegration_RuleSyntaxValidation_MalformedRule(t *testing.T) {
	_, err := fsrules.Parse("ro", "/")

	require.ErrorContains(t, err, "malformed rule")
}

// --- Requirement: Path normalization ---

func TestIntegration_PathNormalization_PathWithRelativeComponents(t *testing.T) {
	rule, err := fsrules.Parse("ro:/home/user/../user/project/./src", "/")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project/src", rule.Path)
}

func TestIntegration_PathNormalization_TrailingSlashRemoval(t *testing.T) {
	rule, err := fsrules.Parse("rw:/home/user/project/", "/")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", rule.Path)
}

func TestIntegration_PathNormalization_RelativePathResolution(t *testing.T) {
	rule, err := fsrules.Parse("rw:./src", "/home/user/myproject")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", rule.Path)
}

func TestIntegration_PathNormalization_RelativePathWithParentTraversal(t *testing.T) {
	rule, err := fsrules.Parse("ro:../shared", "/home/user/myproject")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/shared", rule.Path)
}

// --- Requirement: Duplicate paths rejected ---

func TestIntegration_DuplicatePathsRejected_DuplicatePathsWithDifferentPermissions(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/home/user"),
		rwRule("/home/user"),
	}

	err := fsrules.Validate(rules, "/config.json", nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/home/user")
}

func TestIntegration_DuplicatePathsRejected_IdenticalDuplicateRules(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/usr/bin"),
		roRule("/usr/bin"),
	}

	err := fsrules.Validate(rules, "/config.json", nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/usr/bin")
}

// --- Requirement: Config file cannot be explicitly writable ---

func TestIntegration_ConfigFileCannotBeExplicitlyWritable_ConfigFileExplicitlyWritable(t *testing.T) {
	rules := []fsrules.Rule{
		rwRule("/home/user/project/execave.json"),
	}

	err := fsrules.Validate(rules, "/home/user/project/execave.json", nil)

	require.ErrorContains(t, err, "config file must not be writable")
}

// --- Requirement: Managed paths cannot be targeted by rules ---

func TestIntegration_ManagedPathsCannotBeTargetedByRules_RuleTargetsManagedPathExactly(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/dev"),
	}

	err := fsrules.Validate(rules, "/config.json", []string{"/dev", "/proc", "/tmp"})

	require.ErrorContains(t, err, "managed path")
	require.ErrorContains(t, err, "/dev")
}

func TestIntegration_ManagedPathsCannotBeTargetedByRules_RuleTargetsDescendantOfManagedPath(t *testing.T) {
	rules := []fsrules.Rule{
		rwRule("/proc/self/status"),
	}

	err := fsrules.Validate(rules, "/config.json", []string{"/dev", "/proc", "/tmp"})

	require.ErrorContains(t, err, "managed path")
	require.ErrorContains(t, err, "/proc")
}

func TestIntegration_ManagedPathsCannotBeTargetedByRules_PathWithManagedPrefixInNameIsAllowed(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/home/user/dev"),
	}

	err := fsrules.Validate(rules, "/config.json", []string{"/dev", "/proc", "/tmp"})

	assert.NoError(t, err)
}

// --- Requirement: Most specific rule wins ---

func TestIntegration_MostSpecificRuleWins_SpecificRoOverridesGeneralRw(t *testing.T) {
	rules := []fsrules.Rule{
		rwRule("/home/user/project"),
		roRule("/home/user/project/.git"),
	}
	resolver := fsrules.NewResolver(rules, nil)

	result := resolver.CheckAccess("/home/user/project/.git/config", fsrules.OperationWrite)

	assert.False(t, result.Allowed)
}

func TestIntegration_MostSpecificRuleWins_SpecificRwOverridesGeneralRo(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/home/user"),
		rwRule("/home/user/project"),
	}
	resolver := fsrules.NewResolver(rules, nil)

	result := resolver.CheckAccess("/home/user/project/file.txt", fsrules.OperationWrite)

	assert.True(t, result.Allowed)
}
