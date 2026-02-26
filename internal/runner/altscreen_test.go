package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAltScreenResponse_Active(t *testing.T) {
	assert.True(t, parseAltScreenResponse("\x1b[?1049;1$y"))
}

func TestParseAltScreenResponse_Inactive(t *testing.T) {
	assert.False(t, parseAltScreenResponse("\x1b[?1049;2$y"))
}

func TestParseAltScreenResponse_NotRecognized(t *testing.T) {
	assert.False(t, parseAltScreenResponse("\x1b[?1049;0$y"))
}

func TestParseAltScreenResponse_PermanentlyActive(t *testing.T) {
	assert.True(t, parseAltScreenResponse("\x1b[?1049;3$y"))
}

func TestParseAltScreenResponse_PermanentlyInactive(t *testing.T) {
	assert.False(t, parseAltScreenResponse("\x1b[?1049;4$y"))
}

func TestParseAltScreenResponse_Empty(t *testing.T) {
	assert.False(t, parseAltScreenResponse(""))
}

func TestParseAltScreenResponse_Garbage(t *testing.T) {
	assert.False(t, parseAltScreenResponse("garbage input"))
}

func TestParseAltScreenResponse_TruncatedBeforeValue(t *testing.T) {
	assert.False(t, parseAltScreenResponse("\x1b[?1049;"))
}

func TestQueryAltScreen_NonTerminal(t *testing.T) {
	// In CI and test environments, stdin is not a terminal.
	// queryAltScreen must return false without blocking or panicking.
	assert.False(t, queryAltScreen())
}
