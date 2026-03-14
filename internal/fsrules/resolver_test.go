package fsrules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bbRule constructs a Rule using the public API, mirroring the in-package fsRule helper.
func bbRule(perm fsrules.Permission, path string) fsrules.Rule {
	var permStr string
	switch perm {
	case fsrules.PermissionReadOnly:
		permStr = "ro"
	case fsrules.PermissionReadWrite:
		permStr = "rw"
	case fsrules.PermissionNone:
		permStr = "none"
	case fsrules.PermissionUnknown:
		permStr = "unknown"
	default:
		permStr = "unknown"
	}
	return fsrules.Rule{
		Permission: perm,
		Path:       path,
		RawRule:    permStr + ":" + path,
		SourcePath: "",
	}
}

func TestCheckAccess_UnknownPermission(t *testing.T) {
	// PermissionUnknown in a matched rule is an invariant violation: panic.
	resolver := fsrules.NewResolver([]fsrules.Rule{
		bbRule(fsrules.PermissionUnknown, "/test/path"),
	}, nil)

	assert.Panics(t, func() { resolver.CheckAccess("/test/path/file.txt", fsrules.OperationRead) })
}

func TestCheckAccess_SymlinkDepthLimit(t *testing.T) {
	// Verifies the exact 40-hop limit matching Linux MAXSYMLINKS.
	// The kernel checks if (count >= MAXSYMLINKS) where MAXSYMLINKS=40,
	// so it allows up to 39 hops; the 40th is denied.
	tmpDir := t.TempDir()
	loopA := filepath.Join(tmpDir, "loop-a")
	loopB := filepath.Join(tmpDir, "loop-b")

	err := os.Symlink(loopB, loopA)
	require.NoError(t, err)
	err = os.Symlink(loopA, loopB)
	require.NoError(t, err)

	resolver := fsrules.NewResolver([]fsrules.Rule{
		bbRule(fsrules.PermissionReadOnly, tmpDir),
	}, nil)

	result := resolver.CheckAccess(loopA, fsrules.OperationRead)
	assert.False(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	assert.Len(t, result.Symlink.Hops, 40)
	assert.False(t, result.Symlink.Hops[39].Allowed)
	assert.Nil(t, result.Symlink.Hops[39].Rule)
}

func TestCheckAccess_SymlinkChainThroughManagedPath(t *testing.T) {
	// mount/hop1 -> mount/hop2 -> managed/link -> mount/final
	// Chain enters the managed area at hop2's target; result must be uncertain.
	tmpDir := t.TempDir()
	mountDir := filepath.Join(tmpDir, "mount")
	managedDir := filepath.Join(tmpDir, "managed")

	err := os.Mkdir(mountDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(managedDir, 0o700)
	require.NoError(t, err)

	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(mountDir, "hop2")
	managedLink := filepath.Join(managedDir, "link")
	finalTarget := filepath.Join(mountDir, "final.txt")

	err = os.WriteFile(finalTarget, []byte("data"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(finalTarget, managedLink)
	require.NoError(t, err)
	err = os.Symlink(managedLink, hop2)
	require.NoError(t, err)
	err = os.Symlink(hop2, hop1)
	require.NoError(t, err)

	resolver := fsrules.NewResolver([]fsrules.Rule{
		bbRule(fsrules.PermissionReadWrite, mountDir),
	}, []string{managedDir})

	result := resolver.CheckAccess(hop1, fsrules.OperationRead)

	assert.True(t, result.Uncertain)
	assert.False(t, result.Allowed)

	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 2)
	assert.Equal(t, hop1, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	assert.Equal(t, hop2, result.Symlink.Hops[1].Path)
	assert.True(t, result.Symlink.Hops[1].Allowed)
	assert.True(t, result.Symlink.Unresolvable)
}
