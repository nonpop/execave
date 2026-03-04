package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_InspectingEffectiveConfig_ShowDefaultConfig tests that config show reads
// ./execave.toml from the current working directory by default.
func TestE2E_InspectingEffectiveConfig_ShowDefaultConfig(t *testing.T) {
	workDir := testTempDir(t)
	configPath := filepath.Join(workDir, "execave.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(`fs = ["ro:/usr"]`), 0o600))

	result := runExecave(t, workDir, "config", "show")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "fs = [")
	assert.Contains(t, result.Stdout, "\"ro:/usr\",")
}

// TestE2E_InspectingEffectiveConfig_ShowLayeredConfigWithProvenance tests that
// config show includes source-path comments for layered effective rules.
func TestE2E_InspectingEffectiveConfig_ShowLayeredConfigWithProvenance(t *testing.T) {
	dir := testTempDir(t)
	basePath := filepath.Join(dir, "base.toml")
	rootPath := filepath.Join(dir, "execave.toml")

	baseConfig := `fs = ["ro:/usr"]
net = ["http:api.example.com:443"]
syscall = ["allow:ptrace"]`
	rootConfig := `extends = ["base.toml"]
fs = ["rw:./workspace"]
net = ["none:blocked.example.com:443"]
syscall = ["allow:reboot"]`

	require.NoError(t, os.WriteFile(basePath, []byte(baseConfig), 0o600))
	require.NoError(t, os.WriteFile(rootPath, []byte(rootConfig), 0o600))

	result := runExecave(t, "", "--config", rootPath, "config", "show")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "fs = [")
	assert.Contains(t, result.Stdout, "net = [")
	assert.Contains(t, result.Stdout, "syscall = [")
	assert.Contains(t, result.Stdout, "  # "+basePath+"\n  \"ro:/usr\",\n\n  # "+rootPath+"\n  \"rw:"+filepath.Join(dir, "workspace")+"\",")
	assert.Contains(t, result.Stdout, "\"allow:ptrace\",")
	assert.Contains(t, result.Stdout, "\"allow:reboot\",")
}
