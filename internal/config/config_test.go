package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadTestConfig writes content to a temp file and loads it as a config.
func loadTestConfig(t *testing.T, content string) (*config.Config, error) {
	t.Helper()
	configPath := writeTestConfig(t, content)
	return config.Load(configPath, nil) //nolint:wrapcheck
}

// writeTestConfig writes content to a temp config file and returns the path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.toml")
	err := os.WriteFile(configPath, []byte(content), 0o600)
	require.NoError(t, err)
	return configPath
}

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = [
	"ro:/usr/bin",
	"rw:/home/user/project",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/execave.toml", nil)
	assert.ErrorContains(t, err, "config file not found")
}

func TestLoad_InvalidTOML(t *testing.T) {
	_, err := loadTestConfig(t, "invalid toml [[[")
	assert.ErrorContains(t, err, "parse config")
}

func TestLoad_UnknownResourceType(t *testing.T) {
	_, err := loadTestConfig(t, `fs = ["ro:/usr/bin"]
net = ["dns:allow:example.com"]`)
	assert.ErrorContains(t, err, "invalid action")
}

func TestLoad_ValidNetRule(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = [
	"ro:/usr/bin",
]
net = [
	"http:api.anthropic.com:443",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestLoad_HasNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `net = ["http:api.anthropic.com:443"]`)
	require.NoError(t, err)
	assert.True(t, cfg.HasNetRules())
}

func TestLoad_HasNoNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = ["ro:/usr/bin"]`)
	require.NoError(t, err)
	assert.False(t, cfg.HasNetRules())
}

func TestLoad_InvalidNetRule(t *testing.T) {
	_, err := loadTestConfig(t, `net = ["http:example.com"]`)
	assert.ErrorContains(t, err, "malformed rule")
}

func TestLoad_NetRuleDuplicateIdentityRejected(t *testing.T) {
	_, err := loadTestConfig(t, `net = [
	"http:example.com:443",
	"none:example.com:443",
]`)
	assert.ErrorContains(t, err, "duplicate net rule")
}

func TestLoad_NetRuleMixedPortPatternsRejected(t *testing.T) {
	_, err := loadTestConfig(t, `net = [
	"http:example.com:*",
	"none:example.com:443",
]`)
	assert.ErrorContains(t, err, "mixed port patterns")
}

func TestValidate_NoneWithChildAllowed(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = [
	"none:/home/user/project/.env",
	"ro:/home/user/project/.env/example",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
}

func TestValidate_NoneTerminalValid(t *testing.T) {
	_, err := loadTestConfig(t, `fs = [
	"rw:/home/user/project",
	"none:/home/user/project/.env",
]`)
	assert.NoError(t, err)
}

func TestDuplicatePaths_DifferentPermissions_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `fs = [
	"ro:/home/user",
	"rw:/home/user",
]`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/home/user")
}

func TestDuplicatePaths_IdenticalRules_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `fs = [
	"ro:/path",
	"ro:/path",
]`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/path")
}

func TestDuplicatePaths_TrailingSlash_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `fs = [
	"ro:/foo",
	"ro:/foo/",
]`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/foo")
}

// --- ParseRules tests ---

func TestParseRules_ValidFsAndNetRules(t *testing.T) {
	cfg, err := config.ParseRules(
		[]string{"fs:ro:/usr/bin", "net:http:api.example.com:443"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestParseRules_EmptyRules(t *testing.T) {
	cfg, err := config.ParseRules([]string{}, "/some/dir", "/some/dir/execave.toml", nil)
	require.NoError(t, err)
	assert.Empty(t, cfg.FSRules)
	assert.Empty(t, cfg.NetRules)
}

func TestParseRules_TildeExpansion(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	cfg, err := config.ParseRules(
		[]string{"fs:rw:~/projects"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)
	require.NoError(t, err)
	require.Len(t, cfg.FSRules, 1)
	assert.Equal(t, filepath.Join(homeDir, "projects"), cfg.FSRules[0].Path)
}

func TestParseRules_RelativePathResolvedAgainstConfigDir(t *testing.T) {
	cfg, err := config.ParseRules(
		[]string{"fs:ro:data"},
		"/home/user/myproject", "/home/user/myproject/execave.toml", nil,
	)
	require.NoError(t, err)
	require.Len(t, cfg.FSRules, 1)
	assert.Equal(t, "/home/user/myproject/data", cfg.FSRules[0].Path)
}

func TestParseRules_InvalidRuleRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"badprefix:something"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)
	assert.ErrorContains(t, err, "unknown resource type")
}

func TestParseRules_DuplicatePathsRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"fs:ro:/usr/bin", "fs:rw:/usr/bin"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)
	assert.ErrorContains(t, err, "duplicate path")
}

func TestParseRules_ManagedPathRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"fs:ro:/dev"},
		"/some/dir", "/some/dir/execave.toml", []string{"/dev"},
	)
	assert.ErrorContains(t, err, "managed path")
}

func TestParseRules_ConfigWritabilityRejected(t *testing.T) {
	// The check fires when a rule names the config file path exactly as rw.
	_, err := config.ParseRules(
		[]string{"fs:rw:/home/user/execave.toml"},
		"/home/user", "/home/user/execave.toml", nil,
	)
	assert.ErrorContains(t, err, "config file must not be writable")
}

func TestParseRules_ManagedPathsStoredInConfig(t *testing.T) {
	managedPaths := []string{"/proc", "/dev"}
	cfg, err := config.ParseRules(
		[]string{"fs:ro:/usr/bin"},
		"/some/dir", "/some/dir/execave.toml", managedPaths,
	)
	require.NoError(t, err)
	assert.Equal(t, managedPaths, cfg.ManagedPaths)
}

// --- Syscall rule tests ---

func TestLoad_ValidSyscallRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = ["ro:/usr/lib"]
syscall = ["allow:ptrace", "nolog:bpf"]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Equal(t, []string{"ptrace"}, cfg.SyscallAllowRules)
	assert.Equal(t, []string{"bpf"}, cfg.SyscallNologRules)
}

func TestLoad_InvalidSyscallNameRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["allow:ptraec"]`)
	assert.ErrorContains(t, err, "not a ruleable syscall name")
}

func TestLoad_NonBlockedSyscallNameRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["allow:read"]`)
	assert.ErrorContains(t, err, "not a ruleable syscall name")
}

func TestLoad_DefenseInDepthSyscallRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["allow:syslog"]`)
	assert.ErrorContains(t, err, "not a ruleable syscall name")
}

func TestLoad_DefenseInDepthSyscallNologRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["nolog:syslog"]`)
	assert.ErrorContains(t, err, "not a ruleable syscall name")
}

func TestLoad_DuplicateSyscallAllowRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["allow:ptrace", "allow:ptrace"]`)
	assert.ErrorContains(t, err, "duplicate syscall allow rule")
}

func TestLoad_DuplicateSyscallNologRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["nolog:ptrace", "nolog:ptrace"]`)
	assert.ErrorContains(t, err, "duplicate syscall nolog rule")
}

func TestLoad_SameNameAllowAndNologPermitted(t *testing.T) {
	cfg, err := loadTestConfig(t, `syscall = ["allow:ptrace", "nolog:ptrace"]`)
	require.NoError(t, err)
	assert.Equal(t, []string{"ptrace"}, cfg.SyscallAllowRules)
	assert.Equal(t, []string{"ptrace"}, cfg.SyscallNologRules)
}

func TestLoad_UnknownSyscallActionRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["deny:ptrace"]`)
	assert.ErrorContains(t, err, "unknown syscall action")
}

func TestLoad_MalformedSyscallRuleRejected(t *testing.T) {
	_, err := loadTestConfig(t, `syscall = ["allow"]`)
	assert.ErrorContains(t, err, "malformed syscall rule")
}

func TestLoad_EmptyRulesHasNoSyscallRules(t *testing.T) {
	cfg, err := loadTestConfig(t, ``)
	require.NoError(t, err)
	assert.Empty(t, cfg.SyscallAllowRules)
	assert.Empty(t, cfg.SyscallNologRules)
}

func TestParseTOML_ValidTOML(t *testing.T) {
	content := `fs = ["ro:/usr/bin"]
net = ["http:api.example.com:443"]`
	cfg, err := config.ParseTOML([]byte(content), "/some/dir", "/some/dir/execave.toml", nil)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestParseTOML_EmptyBytes(t *testing.T) {
	cfg, err := config.ParseTOML([]byte{}, "/some/dir", "/some/dir/execave.toml", nil)
	require.NoError(t, err)
	assert.Empty(t, cfg.FSRules)
	assert.Empty(t, cfg.NetRules)
}

func TestParseTOML_InvalidTOML(t *testing.T) {
	_, err := config.ParseTOML([]byte("invalid toml [[["), "/some/dir", "/some/dir/execave.toml", nil)
	assert.ErrorContains(t, err, "parse config")
}

func TestParseTOML_InvalidRules(t *testing.T) {
	content := `fs = ["invalid rule without colon"]`
	_, err := config.ParseTOML([]byte(content), "/some/dir", "/some/dir/execave.toml", nil)
	assert.ErrorContains(t, err, "malformed rule")
}

func TestParseTOML_CommentsPreservedThroughParsing(t *testing.T) {
	content := "# Comment at top\nfs = [\n    # Another comment\n    \"ro:/usr/bin\",\n]"
	cfg, err := config.ParseTOML([]byte(content), "/some/dir", "/some/dir/execave.toml", nil)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
}

func TestParseTOML_NonAbsoluteConfigPathPanics(t *testing.T) {
	assert.Panics(t, func() {
		_, _ = config.ParseTOML([]byte{}, "/some/dir", "relative/execave.toml", nil)
	})
}

func TestPermission_Strictness(t *testing.T) {
	assert.Greater(t, fsrules.PermissionNone, fsrules.PermissionReadOnly)
	assert.Greater(t, fsrules.PermissionReadOnly, fsrules.PermissionReadWrite)
}

func TestValidate_ConfigFileExplicitlyWritable_Rejected(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.toml")

	// Config that makes itself writable
	content := `fs = ["rw:` + configPath + `"]`
	err := os.WriteFile(configPath, []byte(content), 0o600)
	require.NoError(t, err)

	_, err = config.Load(configPath, nil)
	require.ErrorContains(t, err, "config file must not be writable")
}

func TestValidate_ManagedPath_Rejected(t *testing.T) {
	managedPaths := []string{"/proc", "/dev", "/tmp"}

	tests := []struct {
		name    string
		rule    string
		wantErr string
	}{
		{"exact match", `"ro:/proc"`, "/proc"},
		{"subpath", `"rw:/proc/self/status"`, "/proc"},
		{"different managed", `"ro:/dev/null"`, "/dev"},
		{"tmp subpath", `"rw:/tmp/foo"`, "/tmp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `fs = [` + tt.rule + `]`
			configPath := writeTestConfig(t, content)

			_, err := config.Load(configPath, managedPaths)
			require.ErrorContains(t, err, "managed path")
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidate_ManagedPath_SimilarNameAllowed(t *testing.T) {
	managedPaths := []string{"/proc", "/dev", "/tmp"}

	// Paths that look similar but aren't under managed dirs
	tests := []struct {
		name string
		rule string
	}{
		{"proc in name", `"ro:/home/user/proc"`},
		{"procfile", `"ro:/home/user/procfile"`},
		{"dev in project", `"rw:/home/user/dev"`},
		{"tmpdir", `"rw:/home/user/tmpdir"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `fs = [` + tt.rule + `]`
			configPath := writeTestConfig(t, content)

			_, err := config.Load(configPath, managedPaths)
			assert.NoError(t, err)
		})
	}
}
