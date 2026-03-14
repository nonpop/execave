package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InspectingEffectiveConfig_ShowDefaultConfig(t *testing.T) {
	// config show reads ./execave.toml from CWD by default and prints the effective config to stdout.
	s := newScenario(t)

	tests := []struct {
		name       string
		config     string
		wantExit   int
		wantStdout []string
		wantStderr string
	}{
		{
			name:       "single rule type",
			config:     `fs = ["ro:/usr"]`,
			wantExit:   0,
			wantStdout: []string{`"ro:/usr",`},
			wantStderr: "",
		},
		{
			name:       "all rule types",
			config:     "fs = [\"ro:/usr\"]\nnet = [\"http:api.example.com:443\"]\nsyscall = [\"allow:ptrace\"]",
			wantExit:   0,
			wantStdout: []string{`"ro:/usr",`, `"http:api.example.com:443",`, `"allow:ptrace",`},
			wantStderr: "",
		},
		{
			name:       "missing config",
			config:     "",
			wantExit:   1,
			wantStdout: nil,
			wantStderr: "file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workDir := s.givenDir(tt.name)
			if tt.config != "" {
				require.NoError(t, os.WriteFile(workDir.join("execave.toml"), []byte(tt.config), 0o600))
			}

			result := runExecave(t, workDir.String(), "config", "show")

			assertExitCode(t, result, tt.wantExit)
			for _, sub := range tt.wantStdout {
				assert.Contains(t, result.Stdout, sub)
			}
			if tt.wantStderr != "" {
				assert.Contains(t, result.Stderr, tt.wantStderr)
			}
		})
	}
}

func Test_InspectingEffectiveConfig_ShowLayeredConfigWithProvenance(t *testing.T) { //nolint:funlen // e2e scenario test
	// config show annotates each rule with a TOML comment naming the source file.
	// Duplicate rules are deduplicated (first occurrence wins). Synthetic rules
	// injected by the runtime appear under a # <synthetic> comment.
	tests := []struct {
		name          string
		setup         func(t *testing.T, dir string) string
		wantStdout    func(dir string) []string
		wantNotStdout func(dir string) []string
	}{
		{
			name: "two source files: rules attributed to their respective origins",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				basePath := filepath.Join(dir, "base.toml")
				rootPath := filepath.Join(dir, "execave.toml")
				require.NoError(t, os.WriteFile(basePath, []byte("fs = [\"ro:/usr\"]\nnet = [\"http:api.example.com:443\"]\nsyscall = [\"allow:ptrace\"]\nenv = [\"pass:HOME\"]"), 0o600))
				require.NoError(t, os.WriteFile(rootPath, []byte("extends = [\"base.toml\"]\nfs = [\"rw:./workspace\"]\nnet = [\"none:blocked.example.com:443\"]\nsyscall = [\"allow:reboot\"]\nenv = [\"pass:PATH\"]"), 0o600))
				return rootPath
			},
			wantStdout: func(dir string) []string {
				basePath := filepath.Join(dir, "base.toml")
				rootPath := filepath.Join(dir, "execave.toml")
				workspace := filepath.Join(dir, "workspace")
				return []string{
					"  # " + basePath + "\n  \"ro:/usr\",",
					"  # " + rootPath + "\n  \"rw:" + workspace + "\",",
					"  # " + basePath + "\n  \"http:api.example.com:443\",",
					"  # " + rootPath + "\n  \"none:blocked.example.com:443\",",
					"  # " + basePath + "\n  \"allow:ptrace\",",
					"  # " + rootPath + "\n  \"allow:reboot\",",
					"  # " + basePath + "\n  \"pass:HOME\",",
					"  # " + rootPath + "\n  \"pass:PATH\",",
				}
			},
			wantNotStdout: nil,
		},
		{
			name: "three source files: each base attributed separately",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				base1Path := filepath.Join(dir, "base1.toml")
				base2Path := filepath.Join(dir, "base2.toml")
				rootPath := filepath.Join(dir, "execave.toml")
				require.NoError(t, os.WriteFile(base1Path, []byte("fs = [\"ro:/usr\"]"), 0o600))
				require.NoError(t, os.WriteFile(base2Path, []byte("net = [\"http:api.example.com:443\"]"), 0o600))
				require.NoError(t, os.WriteFile(rootPath, []byte("extends = [\"base1.toml\", \"base2.toml\"]\nsyscall = [\"allow:ptrace\"]"), 0o600))
				return rootPath
			},
			wantStdout: func(dir string) []string {
				base1Path := filepath.Join(dir, "base1.toml")
				base2Path := filepath.Join(dir, "base2.toml")
				rootPath := filepath.Join(dir, "execave.toml")
				return []string{
					"  # " + base1Path + "\n  \"ro:/usr\",",
					"  # " + base2Path + "\n  \"http:api.example.com:443\",",
					"  # " + rootPath + "\n  \"allow:ptrace\",",
				}
			},
			wantNotStdout: nil,
		},
		{
			name: "duplicate rule: first occurrence (base) wins for provenance",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				basePath := filepath.Join(dir, "base.toml")
				rootPath := filepath.Join(dir, "execave.toml")
				require.NoError(t, os.WriteFile(basePath, []byte("fs = [\"ro:/usr\"]"), 0o600))
				require.NoError(t, os.WriteFile(rootPath, []byte("extends = [\"base.toml\"]\nfs = [\"ro:/usr\", \"rw:./workspace\"]"), 0o600))
				return rootPath
			},
			wantStdout: func(dir string) []string {
				basePath := filepath.Join(dir, "base.toml")
				rootPath := filepath.Join(dir, "execave.toml")
				workspace := filepath.Join(dir, "workspace")
				return []string{
					"  # " + basePath + "\n  \"ro:/usr\",",
					"  # " + rootPath + "\n  \"rw:" + workspace + "\",",
				}
			},
			wantNotStdout: func(dir string) []string {
				rootPath := filepath.Join(dir, "execave.toml")
				// The duplicate ro:/usr from root must not appear under root's source comment.
				return []string{"  # " + rootPath + "\n  \"ro:/usr\","}
			},
		},
		{
			name: "synthetic rule: forced-RO config file appears under synthetic comment",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				rootPath := filepath.Join(dir, "execave.toml")
				// rw:./ makes the config file's own directory writable, triggering a
				// forced synthetic read-only rule for the config file itself.
				require.NoError(t, os.WriteFile(rootPath, []byte("fs = [\"rw:./\"]"), 0o600))
				return rootPath
			},
			wantStdout: func(dir string) []string {
				configPath := filepath.Join(dir, "execave.toml")
				return []string{"  # <synthetic>\n  \"ro:" + configPath + "\","}
			},
			wantNotStdout: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testTempDir(t)
			configPath := tt.setup(t, dir)

			result := runExecave(t, "", "--config", configPath, "config", "show")

			assertExitCode(t, result, 0)
			for _, sub := range tt.wantStdout(dir) {
				assert.Contains(t, result.Stdout, sub)
			}
			if tt.wantNotStdout != nil {
				for _, sub := range tt.wantNotStdout(dir) {
					assert.NotContains(t, result.Stdout, sub)
				}
			}
		})
	}
}
