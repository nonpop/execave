package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- parseBwrapVersion ---

func TestParseBwrapVersion_ValidInput(t *testing.T) {
	v, err := parseBwrapVersion("bwrap 0.11.0\n")
	require.NoError(t, err)
	assert.Equal(t, [3]int{0, 11, 0}, v)
}

func TestParseBwrapVersion_ValidInputWithTrailingText(t *testing.T) {
	v, err := parseBwrapVersion("bwrap 0.11.5\nsome other line\n")
	require.NoError(t, err)
	assert.Equal(t, [3]int{0, 11, 5}, v)
}

func TestParseBwrapVersion_HigherVersion(t *testing.T) {
	v, err := parseBwrapVersion("bwrap 1.2.3\n")
	require.NoError(t, err)
	assert.Equal(t, [3]int{1, 2, 3}, v)
}

func TestParseBwrapVersion_EmptyOutput_Error(t *testing.T) {
	_, err := parseBwrapVersion("")
	assert.Error(t, err)
}

func TestParseBwrapVersion_NoVersionToken_Error(t *testing.T) {
	_, err := parseBwrapVersion("bwrap\n")
	assert.Error(t, err)
}

func TestParseBwrapVersion_NonNumericVersion_Error(t *testing.T) {
	_, err := parseBwrapVersion("bwrap notaversion\n")
	assert.Error(t, err)
}

func TestParseBwrapVersion_MissingPatchComponent_Error(t *testing.T) {
	_, err := parseBwrapVersion("bwrap 0.11\n")
	assert.Error(t, err)
}

// --- parseStraceVersion ---

func TestParseStraceVersion_ValidFirstLine(t *testing.T) {
	v, err := parseStraceVersion("strace -- version 6.18\n")
	require.NoError(t, err)
	assert.Equal(t, [2]int{6, 18}, v)
}

func TestParseStraceVersion_ValidSecondLine(t *testing.T) {
	v, err := parseStraceVersion("strace\nversion 6.18 something\n")
	require.NoError(t, err)
	assert.Equal(t, [2]int{6, 18}, v)
}

func TestParseStraceVersion_ExtractsFirstMatch(t *testing.T) {
	v, err := parseStraceVersion("strace 6.19 (other 7.0)\n")
	require.NoError(t, err)
	assert.Equal(t, [2]int{6, 19}, v)
}

func TestParseStraceVersion_EmptyOutput_Error(t *testing.T) {
	_, err := parseStraceVersion("")
	assert.Error(t, err)
}

func TestParseStraceVersion_NoVersionMatch_Error(t *testing.T) {
	_, err := parseStraceVersion("strace\nno version here\n")
	assert.Error(t, err)
}

// --- bwrapCompatLevel ---

func TestBwrapCompatLevel_OlderMinor_Error(t *testing.T) {
	assert.Equal(t, compatError, bwrapCompatLevel([3]int{0, 10, 0}))
}

func TestBwrapCompatLevel_OlderMinorWithPatch_Error(t *testing.T) {
	assert.Equal(t, compatError, bwrapCompatLevel([3]int{0, 10, 5}))
}

func TestBwrapCompatLevel_PinnedVersion_OK(t *testing.T) {
	assert.Equal(t, compatOK, bwrapCompatLevel([3]int{0, 11, 0}))
}

func TestBwrapCompatLevel_SameMinorHigherPatch_OK(t *testing.T) {
	assert.Equal(t, compatOK, bwrapCompatLevel([3]int{0, 11, 5}))
}

func TestBwrapCompatLevel_HigherMinor_Warn(t *testing.T) {
	assert.Equal(t, compatWarn, bwrapCompatLevel([3]int{0, 12, 0}))
}

func TestBwrapCompatLevel_HighMinorStill0x_Warn(t *testing.T) {
	assert.Equal(t, compatWarn, bwrapCompatLevel([3]int{0, 99, 9}))
}

func TestBwrapCompatLevel_MajorBump_Error(t *testing.T) {
	assert.Equal(t, compatError, bwrapCompatLevel([3]int{1, 0, 0}))
}

// --- straceCompatLevel ---

func TestStraceCompatLevel_OlderMinor_Error(t *testing.T) {
	assert.Equal(t, compatError, straceCompatLevel([2]int{6, 17}))
}

func TestStraceCompatLevel_PinnedVersion_OK(t *testing.T) {
	assert.Equal(t, compatOK, straceCompatLevel([2]int{6, 18}))
}

func TestStraceCompatLevel_HigherMinor_Warn(t *testing.T) {
	assert.Equal(t, compatWarn, straceCompatLevel([2]int{6, 19}))
}

func TestStraceCompatLevel_HighMinorStill6x_Warn(t *testing.T) {
	assert.Equal(t, compatWarn, straceCompatLevel([2]int{6, 99}))
}

func TestStraceCompatLevel_MajorBump_Error(t *testing.T) {
	assert.Equal(t, compatError, straceCompatLevel([2]int{7, 0}))
}
