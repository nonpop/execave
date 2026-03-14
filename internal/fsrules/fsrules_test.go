package fsrules_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathNormalization_PathWithRelativeComponents(t *testing.T) {
	rule, err := fsrules.ParseRule("ro:/home/user/../user/project/./src", "/", "")

	require.NoError(t, err)
	assert.Equal(t, "/home/user/project/src", rule.Path)
}

func TestDuplicatePathsRejected_SameFileDuplicateShowsSourceOnce(t *testing.T) {
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

func TestTildeExpansionInPaths_BareTildeExpandedToHomeDirectory(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseRule("ro:~", "/", "")

	require.NoError(t, err)
	assert.Equal(t, homeDir, rule.Path)
}

func TestTildeExpansionInPaths_TildePathCleanedAfterExpansion(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	rule, err := fsrules.ParseRule("rw:~/project/../other", "/", "")

	require.NoError(t, err)
	assert.Equal(t, homeDir+"/other", rule.Path)
}

func TestTildeExpandedPathsParticipateInValidation_TildePathTargetingConfigFileRejected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	configPath := homeDir + "/myproject/execave.toml"
	rule, err := fsrules.ParseRule("rw:~/myproject/execave.toml", "/", "")
	require.NoError(t, err)

	err = fsrules.ValidateRules([]fsrules.Rule{rule}, []string{configPath}, nil)

	require.ErrorContains(t, err, "must not be writable")
}

func TestCanonicalRoundTrip(t *testing.T) {
	cases := []string{
		"rw:/home/user",
		"ro:/usr/bin",
		"none:/secrets",
	}
	for _, tt := range cases {
		t.Run(tt, func(t *testing.T) {
			rule1, err := fsrules.ParseRule(tt, "/tmp", "")
			require.NoError(t, err)
			canonical1 := rule1.Canonical()

			rule2, err := fsrules.ParseRule(canonical1, "/tmp", "")
			require.NoError(t, err)
			canonical2 := rule2.Canonical()

			assert.Equal(t, canonical1, canonical2)
		})
	}
}
