package fsrules_test

import (
	"os"
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func roRule(path string) fsrules.AccessRule {
	return fsrules.AccessRule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
		SourcePath: "",
	}
}

func rwRule(path string) fsrules.AccessRule {
	return fsrules.AccessRule{
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "rw:" + path,
		SourcePath: "",
	}
}

// --- Requirement: Rule syntax validation ---

func TestIntegration_RuleSyntaxValidation_InvalidPermissionType(t *testing.T) {
	_, err := fsrules.ParseAccessRule("readonly:/path", "/")

	require.ErrorContains(t, err, "invalid permission type")
}

func TestIntegration_RuleSyntaxValidation_MalformedRule(t *testing.T) {
	_, err := fsrules.ParseAccessRule("ro", "/")

	require.ErrorContains(t, err, "malformed rule")
}

// --- Requirement: Path normalization ---

func TestIntegration_PathNormalization_PathWithRelativeComponents(t *testing.T) {
	rule, err := fsrules.ParseAccessRule("ro:/home/user/../user/project/./src", "/")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project/src", rule.Path)
}

func TestIntegration_PathNormalization_TrailingSlashRemoval(t *testing.T) {
	rule, err := fsrules.ParseAccessRule("rw:/home/user/project/", "/")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", rule.Path)
}

func TestIntegration_PathNormalization_RelativePathResolution(t *testing.T) {
	rule, err := fsrules.ParseAccessRule("rw:./src", "/home/user/myproject")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", rule.Path)
}

func TestIntegration_PathNormalization_RelativePathWithParentTraversal(t *testing.T) {
	rule, err := fsrules.ParseAccessRule("ro:../shared", "/home/user/myproject")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/shared", rule.Path)
}

// --- Requirement: Duplicate paths rejected ---

func TestIntegration_DuplicatePathsRejected_DuplicatePathsWithDifferentPermissions(t *testing.T) {
	rules := []fsrules.AccessRule{
		roRule("/home/user"),
		rwRule("/home/user"),
	}

	err := fsrules.ValidateAccessRules(rules, []string{"/config.json"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/home/user")
}

func TestIntegration_DuplicatePathsRejected_IdenticalDuplicateRules(t *testing.T) {
	rules := []fsrules.AccessRule{
		roRule("/usr/bin"),
		roRule("/usr/bin"),
	}

	err := fsrules.ValidateAccessRules(rules, []string{"/config.json"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/usr/bin")
}

// --- Requirement: Config file cannot be explicitly writable ---

func TestIntegration_ConfigFileCannotBeExplicitlyWritable_ConfigFileExplicitlyWritable(t *testing.T) {
	rules := []fsrules.AccessRule{
		rwRule("/home/user/project/execave.json"),
	}

	err := fsrules.ValidateAccessRules(rules, []string{"/home/user/project/execave.json"}, nil)

	require.ErrorContains(t, err, "must not be writable")
}

// --- Requirement: Managed paths cannot be targeted by rules ---

func TestIntegration_ManagedPathsCannotBeTargetedByRules_RuleTargetsManagedPathExactly(t *testing.T) {
	rules := []fsrules.AccessRule{
		roRule("/dev"),
	}

	err := fsrules.ValidateAccessRules(rules, []string{"/config.json"}, []string{"/dev", "/proc", "/tmp"})

	require.ErrorContains(t, err, "managed path")
	require.ErrorContains(t, err, "/dev")
}

func TestIntegration_ManagedPathsCannotBeTargetedByRules_RuleTargetsDescendantOfManagedPath(t *testing.T) {
	rules := []fsrules.AccessRule{
		rwRule("/proc/self/status"),
	}

	err := fsrules.ValidateAccessRules(rules, []string{"/config.json"}, []string{"/dev", "/proc", "/tmp"})

	require.ErrorContains(t, err, "managed path")
	require.ErrorContains(t, err, "/proc")
}

func TestIntegration_ManagedPathsCannotBeTargetedByRules_PathWithManagedPrefixInNameIsAllowed(t *testing.T) {
	rules := []fsrules.AccessRule{
		roRule("/home/user/dev"),
	}

	err := fsrules.ValidateAccessRules(rules, []string{"/config.json"}, []string{"/dev", "/proc", "/tmp"})

	assert.NoError(t, err)
}

// --- Requirement: Tilde expansion in paths ---

func TestIntegration_TildeExpansionInPaths_TildeSlashPathExpandedToAbsolute(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseAccessRule("rw:~/project", "/")

	require.NoError(t, err)
	assert.Equal(t, homeDir+"/project", rule.Path)
}

func TestIntegration_TildeExpansionInPaths_BareTildeExpandedToHomeDirectory(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseAccessRule("ro:~", "/")

	require.NoError(t, err)
	assert.Equal(t, homeDir, rule.Path)
}

func TestIntegration_TildeExpansionInPaths_TildePathCleanedAfterExpansion(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseAccessRule("rw:~/project/../other", "/")

	require.NoError(t, err)
	assert.Equal(t, homeDir+"/other", rule.Path)
}

func TestIntegration_TildeExpansionInPaths_TildeUsernameRejected(t *testing.T) {
	_, err := fsrules.ParseAccessRule("ro:~otheruser/data", "/home/user")

	require.ErrorContains(t, err, "~username")
}

// --- Requirement: Tilde-expanded paths participate in validation ---

func TestIntegration_TildeExpandedPathsParticipateInValidation_TildeAndAbsolutePathDuplicateDetected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tildeRule, err := fsrules.ParseAccessRule("ro:~/project", "/")
	require.NoError(t, err)

	rules := []fsrules.AccessRule{
		tildeRule,
		roRule(homeDir + "/project"),
	}

	err = fsrules.ValidateAccessRules(rules, []string{"/config.toml"}, nil)

	require.ErrorContains(t, err, "duplicate path")
}

func TestIntegration_TildeExpandedPathsParticipateInValidation_TildePathAndEquivalentRelativePathDuplicateDetected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tildeRule, err := fsrules.ParseAccessRule("rw:~/project", homeDir)
	require.NoError(t, err)

	relRule, err := fsrules.ParseAccessRule("rw:project", homeDir)
	require.NoError(t, err)

	rules := []fsrules.AccessRule{tildeRule, relRule}

	err = fsrules.ValidateAccessRules(rules, []string{"/config.toml"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, homeDir+"/project")
}

func TestIntegration_TildeExpandedPathsParticipateInValidation_TildePathTargetingConfigFileRejected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	configPath := homeDir + "/myproject/execave.toml"
	rule, err := fsrules.ParseAccessRule("rw:~/myproject/execave.toml", "/")
	require.NoError(t, err)

	err = fsrules.ValidateAccessRules([]fsrules.AccessRule{rule}, []string{configPath}, nil)

	require.ErrorContains(t, err, "must not be writable")
}

// --- Requirement: Most specific rule wins ---

func TestIntegration_MostSpecificRuleWins_SpecificRoOverridesGeneralRw(t *testing.T) {
	rules := []fsrules.AccessRule{
		rwRule("/home/user/project"),
		roRule("/home/user/project/.git"),
	}
	resolver := fsrules.NewAccessResolver(rules, nil)

	result := resolver.CheckAccess("/home/user/project/.git/config", fsrules.OperationWrite)

	assert.False(t, result.Allowed)
}

// --- Requirement: Log rule syntax validation ---

func TestIntegration_LogRuleSyntaxValidation_ValidNologRule(t *testing.T) {
	rule, err := fsrules.ParseLogRule("nolog:/home/user/project", "/")

	require.NoError(t, err)
	assert.False(t, rule.Visible)
	assert.Equal(t, "/home/user/project", rule.Path)
}

func TestIntegration_LogRuleSyntaxValidation_ValidLogRule(t *testing.T) {
	rule, err := fsrules.ParseLogRule("log:/home/user/project", "/")

	require.NoError(t, err)
	assert.True(t, rule.Visible)
	assert.Equal(t, "/home/user/project", rule.Path)
}

func TestIntegration_LogRuleSyntaxValidation_InvalidVisibilityType(t *testing.T) {
	_, err := fsrules.ParseLogRule("hide:/path", "/")

	require.ErrorContains(t, err, "invalid visibility type")
}

func TestIntegration_LogRuleSyntaxValidation_MalformedLogRule(t *testing.T) {
	_, err := fsrules.ParseLogRule("nolog", "/")

	require.ErrorContains(t, err, "malformed rule")
}

func TestIntegration_LogRuleSyntaxValidation_TildeExpansionInLogRulePath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseLogRule("nolog:~/project", "/home/user")

	require.NoError(t, err)
	assert.Equal(t, homeDir+"/project", rule.Path)
}

func TestIntegration_LogRuleSyntaxValidation_RelativePathResolutionInLogRule(t *testing.T) {
	rule, err := fsrules.ParseLogRule("nolog:data", "/home/user/myproject")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/data", rule.Path)
}

// --- Requirement: Log rule validation ---

func nologRule(path string) fsrules.LogRule {
	return fsrules.LogRule{Visible: false, Path: path, RawRule: "nolog:" + path, SourcePath: ""}
}

func logRule(path string) fsrules.LogRule {
	return fsrules.LogRule{Visible: true, Path: path, RawRule: "log:" + path, SourcePath: ""}
}

func TestIntegration_LogRuleValidation_DuplicateLogRulePathsRejected(t *testing.T) {
	rules := []fsrules.LogRule{nologRule("/home/user"), logRule("/home/user")}

	err := fsrules.ValidateLogRules(rules)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/home/user")
}

func TestIntegration_LogRuleValidation_IdenticalDuplicateLogRulesRejected(t *testing.T) {
	rules := []fsrules.LogRule{nologRule("/usr/bin"), nologRule("/usr/bin")}

	err := fsrules.ValidateLogRules(rules)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/usr/bin")
}

func TestIntegration_LogRuleValidation_SamePathInAccessAndLogRulesAllowed(t *testing.T) {
	logRules := []fsrules.LogRule{nologRule("/usr/lib")}

	err := fsrules.ValidateLogRules(logRules)

	assert.NoError(t, err)
}

// --- Requirement: Log rule resolution ---

func TestIntegration_LogRuleResolution_NologHidesEntriesUnderMatchingPath(t *testing.T) {
	rules := []fsrules.LogRule{nologRule("/home/user/project")}
	resolver := fsrules.NewLogResolver(rules)

	assert.False(t, resolver.Visible("/home/user/project/cache/data"))
}

func TestIntegration_LogRuleResolution_LogOverridesNologForMoreSpecificPath(t *testing.T) {
	rules := []fsrules.LogRule{nologRule("/home/user/project"), logRule("/home/user/project/secret")}
	resolver := fsrules.NewLogResolver(rules)

	assert.True(t, resolver.Visible("/home/user/project/secret/key.pem"))
}

func TestIntegration_LogRuleResolution_NoMatchingLogRuleDefaultsToVisible(t *testing.T) {
	rules := []fsrules.LogRule{nologRule("/home/user/project")}
	resolver := fsrules.NewLogResolver(rules)

	assert.True(t, resolver.Visible("/usr/lib/libc.so"))
}

func TestIntegration_LogRuleResolution_ExactPathMatch(t *testing.T) {
	rules := []fsrules.LogRule{nologRule("/home/user/project")}
	resolver := fsrules.NewLogResolver(rules)

	assert.False(t, resolver.Visible("/home/user/project"))
}

func TestIntegration_LogRuleResolution_NestedNologOverridesLog(t *testing.T) {
	rules := []fsrules.LogRule{
		nologRule("/home/user"),
		logRule("/home/user/project"),
		nologRule("/home/user/project/vendor"),
	}
	resolver := fsrules.NewLogResolver(rules)

	assert.False(t, resolver.Visible("/home/user/project/vendor/lib.go"))
}

// --- Requirement: Most specific rule wins ---

func TestIntegration_MostSpecificRuleWins_SpecificRwOverridesGeneralRo(t *testing.T) {
	rules := []fsrules.AccessRule{
		roRule("/home/user"),
		rwRule("/home/user/project"),
	}
	resolver := fsrules.NewAccessResolver(rules, nil)

	result := resolver.CheckAccess("/home/user/project/file.txt", fsrules.OperationWrite)

	assert.True(t, result.Allowed)
}
