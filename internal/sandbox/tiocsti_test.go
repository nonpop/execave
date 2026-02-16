package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTiocSTIBlocked_SysctlContainsZero(t *testing.T) {
	tmpDir := t.TempDir()
	fakeSysctl := filepath.Join(tmpDir, "legacy_tiocsti")
	require.NoError(t, os.WriteFile(fakeSysctl, []byte("0\n"), 0o600))

	assert.True(t, tiocSTIBlocked(fakeSysctl))
}

func TestTiocSTIBlocked_SysctlContainsOne(t *testing.T) {
	tmpDir := t.TempDir()
	fakeSysctl := filepath.Join(tmpDir, "legacy_tiocsti")
	require.NoError(t, os.WriteFile(fakeSysctl, []byte("1\n"), 0o600))

	assert.False(t, tiocSTIBlocked(fakeSysctl))
}

func TestTiocSTIBlocked_FileAbsent(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "nonexistent")

	assert.False(t, tiocSTIBlocked(nonExistentPath))
}

func TestTiocSTIBlocked_UnexpectedContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace", "   \n"},
		{"non-numeric", "invalid"},
		{"leading zero", "00"},
		{"multiple lines", "0\n1\n"},
		{"negative number", "-1"},
		{"large number", "999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			fakeSysctl := filepath.Join(tmpDir, "legacy_tiocsti")
			require.NoError(t, os.WriteFile(fakeSysctl, []byte(tt.content), 0o600))

			assert.False(t, tiocSTIBlocked(fakeSysctl))
		})
	}
}
