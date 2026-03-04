package fsrules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func roRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
		SourcePath: "",
	}
}

func rwRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "rw:" + path,
		SourcePath: "",
	}
}

// --- Requirement: Rule syntax validation ---

func TestIntegration_RuleSyntaxValidation_InvalidPermissionType(t *testing.T) {
	_, err := fsrules.ParseRule("readonly:/path", "/", "")

	require.ErrorContains(t, err, "invalid permission type")
}

func TestIntegration_RuleSyntaxValidation_MalformedRule(t *testing.T) {
	_, err := fsrules.ParseRule("ro", "/", "")

	require.ErrorContains(t, err, "malformed rule")
}

// --- Requirement: Path normalization ---

func TestIntegration_PathNormalization_PathWithRelativeComponents(t *testing.T) {
	rule, err := fsrules.ParseRule("ro:/home/user/../user/project/./src", "/", "")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project/src", rule.Path)
}

func TestIntegration_PathNormalization_TrailingSlashRemoval(t *testing.T) {
	rule, err := fsrules.ParseRule("rw:/home/user/project/", "/", "")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", rule.Path)
}

func TestIntegration_PathNormalization_RelativePathResolution(t *testing.T) {
	rule, err := fsrules.ParseRule("rw:./src", "/home/user/myproject", "")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", rule.Path)
}

func TestIntegration_PathNormalization_RelativePathWithParentTraversal(t *testing.T) {
	rule, err := fsrules.ParseRule("ro:../shared", "/home/user/myproject", "")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/shared", rule.Path)
}

// --- Requirement: Duplicate paths rejected ---

func TestIntegration_DuplicatePathsRejected_DuplicatePathsWithDifferentPermissions(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/home/user"),
		rwRule("/home/user"),
	}

	err := fsrules.ValidateRules(rules, []string{"/config.json"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/home/user")
}

func TestIntegration_DuplicatePathsRejected_IdenticalDuplicateRules(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/usr/bin"),
		roRule("/usr/bin"),
	}

	err := fsrules.ValidateRules(rules, []string{"/config.json"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/usr/bin")
}

func TestIntegration_DuplicatePathsRejected_SameFileDuplicateShowsSourceOnce(t *testing.T) {
	rules := []fsrules.Rule{
		{Permission: fsrules.PermissionReadOnly, Path: "/home/user", RawRule: "ro:/home/user", SourcePath: "/etc/execave.json"},
		{Permission: fsrules.PermissionReadWrite, Path: "/home/user", RawRule: "rw:/home/user", SourcePath: "/etc/execave.json"},
	}

	err := fsrules.ValidateRules(rules, []string{"/etc/execave.json"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, "/home/user")
	require.ErrorContains(t, err, "/etc/execave.json")
	assert.Equal(t, 1, strings.Count(err.Error(), "/etc/execave.json"))
}

// --- Requirement: Config file cannot be explicitly writable ---

func TestIntegration_ConfigFileCannotBeExplicitlyWritable_ConfigFileExplicitlyWritable(t *testing.T) {
	rules := []fsrules.Rule{
		rwRule("/home/user/project/execave.json"),
	}

	err := fsrules.ValidateRules(rules, []string{"/home/user/project/execave.json"}, nil)

	require.ErrorContains(t, err, "must not be writable")
}

// --- Requirement: Managed paths cannot be targeted by rules ---

func TestIntegration_ManagedPathsCannotBeTargetedByRules_RuleTargetsManagedPathExactly(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/dev"),
	}

	err := fsrules.ValidateRules(rules, []string{"/config.json"}, []string{"/dev", "/proc", "/tmp"})

	require.ErrorContains(t, err, "managed path")
	require.ErrorContains(t, err, "/dev")
}

func TestIntegration_ManagedPathsCannotBeTargetedByRules_RuleTargetsDescendantOfManagedPath(t *testing.T) {
	rules := []fsrules.Rule{
		rwRule("/proc/self/status"),
	}

	err := fsrules.ValidateRules(rules, []string{"/config.json"}, []string{"/dev", "/proc", "/tmp"})

	require.ErrorContains(t, err, "managed path")
	require.ErrorContains(t, err, "/proc")
}

func TestIntegration_ManagedPathsCannotBeTargetedByRules_PathWithManagedPrefixInNameIsAllowed(t *testing.T) {
	rules := []fsrules.Rule{
		roRule("/home/user/dev"),
	}

	err := fsrules.ValidateRules(rules, []string{"/config.json"}, []string{"/dev", "/proc", "/tmp"})

	assert.NoError(t, err)
}

// --- Requirement: Tilde expansion in paths ---

func TestIntegration_TildeExpansionInPaths_TildeSlashPathExpandedToAbsolute(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseRule("rw:~/project", "/", "")

	require.NoError(t, err)
	assert.Equal(t, homeDir+"/project", rule.Path)
}

func TestIntegration_TildeExpansionInPaths_BareTildeExpandedToHomeDirectory(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseRule("ro:~", "/", "")

	require.NoError(t, err)
	assert.Equal(t, homeDir, rule.Path)
}

func TestIntegration_TildeExpansionInPaths_TildePathCleanedAfterExpansion(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseRule("rw:~/project/../other", "/", "")

	require.NoError(t, err)
	assert.Equal(t, homeDir+"/other", rule.Path)
}

func TestIntegration_TildeExpansionInPaths_TildeUsernameRejected(t *testing.T) {
	_, err := fsrules.ParseRule("ro:~otheruser/data", "/home/user", "")

	require.ErrorContains(t, err, "~username")
}

// --- Requirement: Tilde-expanded paths participate in validation ---

func TestIntegration_TildeExpandedPathsParticipateInValidation_TildeAndAbsolutePathDuplicateDetected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tildeRule, err := fsrules.ParseRule("ro:~/project", "/", "")
	require.NoError(t, err)

	rules := []fsrules.Rule{
		tildeRule,
		roRule(homeDir + "/project"),
	}

	err = fsrules.ValidateRules(rules, []string{"/config.toml"}, nil)

	require.ErrorContains(t, err, "duplicate path")
}

func TestIntegration_TildeExpandedPathsParticipateInValidation_TildePathAndEquivalentRelativePathDuplicateDetected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tildeRule, err := fsrules.ParseRule("rw:~/project", homeDir, "")
	require.NoError(t, err)

	relRule, err := fsrules.ParseRule("rw:project", homeDir, "")
	require.NoError(t, err)

	rules := []fsrules.Rule{tildeRule, relRule}

	err = fsrules.ValidateRules(rules, []string{"/config.toml"}, nil)

	require.ErrorContains(t, err, "duplicate path")
	require.ErrorContains(t, err, homeDir+"/project")
}

func TestIntegration_TildeExpandedPathsParticipateInValidation_TildePathTargetingConfigFileRejected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	configPath := homeDir + "/myproject/execave.toml"
	rule, err := fsrules.ParseRule("rw:~/myproject/execave.toml", "/", "")
	require.NoError(t, err)

	err = fsrules.ValidateRules([]fsrules.Rule{rule}, []string{configPath}, nil)

	require.ErrorContains(t, err, "must not be writable")
}

// --- Requirement: Symlink resolution stops when path enters a managed directory ---

func TestIntegration_SymlinkResolutionStopsWhenPathEntersManagedDirectory_SymlinkPointsToAncestorOfManagedPath(t *testing.T) {
	tmpDir := t.TempDir()
	mountDir := filepath.Join(tmpDir, "mount")
	managedParent := filepath.Join(tmpDir, "managed_parent")
	managedSub := filepath.Join(managedParent, "sub")

	require.NoError(t, os.MkdirAll(mountDir, 0o700))
	require.NoError(t, os.MkdirAll(managedSub, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(managedSub, "file"), []byte("data"), 0o600))

	linkPath := filepath.Join(mountDir, "link")
	require.NoError(t, os.Symlink(managedParent, linkPath))

	resolver := fsrules.NewResolver([]fsrules.Rule{rwRule(mountDir), roRule(managedParent)}, []string{managedSub})

	result := resolver.CheckAccess(filepath.Join(linkPath, "sub", "file"), fsrules.OperationRead)

	assert.True(t, result.Uncertain)
	assert.False(t, result.Allowed)
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
