package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IteratingConfig_InvalidTOMLRejectedBeforeExecution(t *testing.T) {
	// Invalid TOML is rejected at config load time; the command never executes.
	s := newScenario(t)
	s.givenRawConfig("rules = [")

	s.whenRun("sh", "-c", "echo SHOULD_NOT_RUN")

	s.thenExitCode(1)
	s.thenStderrContains("parse")
	assert.Empty(t, s.lastResult.Stdout)
}
