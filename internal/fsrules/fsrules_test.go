package fsrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRule_Valid(t *testing.T) {
	tests := []struct {
		name         string
		rule         string
		expectedPerm Permission
		expectedPath string
	}{
		{"read-write", "rw:/home/user", PermissionReadWrite, "/home/user"},
		{"read-only", "ro:/usr/bin", PermissionReadOnly, "/usr/bin"},
		{"none", "none:/secrets", PermissionNone, "/secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := ParseRule(tt.rule, "/tmp", "")
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPerm, rule.Permission)
			assert.Equal(t, tt.expectedPath, rule.Path)
		})
	}
}

func TestParseRule_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{"missing-path", "ro"},
		{"no-colons", "invalid"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRule(tt.rule, "/tmp", "")
			assert.ErrorContains(t, err, "malformed rule")
		})
	}
}

func TestParseRule_InvalidPermission(t *testing.T) {
	_, err := ParseRule("readonly:/path", "/tmp", "")
	assert.ErrorContains(t, err, "invalid permission type")
}

// --- Identity ---

func TestIdentity_ReadWriteRule(t *testing.T) {
	rule, err := ParseRule("rw:/home/user", "/tmp", "")
	require.NoError(t, err)
	assert.Equal(t, "rw:/home/user", rule.Canonical())
}

func TestIdentity_ReadOnlyRule(t *testing.T) {
	rule, err := ParseRule("ro:/usr/bin", "/tmp", "")
	require.NoError(t, err)
	assert.Equal(t, "ro:/usr/bin", rule.Canonical())
}

func TestIdentity_NoneRule(t *testing.T) {
	rule, err := ParseRule("none:/secrets", "/tmp", "")
	require.NoError(t, err)
	assert.Equal(t, "none:/secrets", rule.Canonical())
}

func TestCanonicalRoundTrip(t *testing.T) {
	cases := []string{
		"rw:/home/user",
		"ro:/usr/bin",
		"none:/secrets",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			rule1, err := ParseRule(tc, "/tmp", "")
			require.NoError(t, err)
			canonical1 := rule1.Canonical()

			rule2, err := ParseRule(canonical1, "/tmp", "")
			require.NoError(t, err)
			canonical2 := rule2.Canonical()

			assert.Equal(t, canonical1, canonical2)
		})
	}
}
