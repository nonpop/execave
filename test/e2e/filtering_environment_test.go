package e2e_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_FilteringEnvironment_DefaultDenyHostVarAbsentWithoutEnvRules(t *testing.T) {
	// Without env rules, no host environment variables are visible inside the sandbox.
	s := newScenario(t)
	t.Setenv("EXECAVE_TEST_SECRET", "should-not-leak")
	s.givenRules()

	s.whenRun("sh", "-c", "echo ${EXECAVE_TEST_SECRET:-absent}")

	s.thenExitCode(0)
	s.thenStdoutContains("absent")
}

func Test_FilteringEnvironment_PassRuleMakesHostVarVisible(t *testing.T) {
	// A pass:HOME rule forwards the host HOME into the sandbox.
	s := newScenario(t)
	s.givenRules("env:pass:HOME")

	s.whenRun("sh", "-c", `echo ${HOME:-absent}`)

	s.thenExitCode(0)
	s.thenStdoutContains("/home/")
}

func Test_FilteringEnvironment_OnlyListedVarsVisible(t *testing.T) {
	// A single pass rule makes only that var visible; unlisted vars are absent.
	s := newScenario(t)
	t.Setenv("EXECAVE_ALLOWED", "allowed-value")
	t.Setenv("EXECAVE_BLOCKED", "blocked-value")
	s.givenRules("env:pass:EXECAVE_ALLOWED")

	s.whenRun("sh", "-c", `echo "allowed=${EXECAVE_ALLOWED:-absent} blocked=${EXECAVE_BLOCKED:-absent}"`)

	s.thenExitCode(0)
	s.thenStdoutContains("allowed=allowed-value")
	s.thenStdoutContains("blocked=absent")
}

func Test_FilteringEnvironment_MultiplePassRulesAllowMultipleVars(t *testing.T) {
	// Multiple pass rules each forward their respective var; unlisted vars are absent.
	s := newScenario(t)
	t.Setenv("EXECAVE_VAR_A", "value-a")
	t.Setenv("EXECAVE_VAR_B", "value-b")
	t.Setenv("EXECAVE_VAR_C", "blocked-value")
	s.givenRules("env:pass:EXECAVE_VAR_A", "env:pass:EXECAVE_VAR_B")

	s.whenRun("sh", "-c", `echo "a=${EXECAVE_VAR_A:-absent} b=${EXECAVE_VAR_B:-absent} c=${EXECAVE_VAR_C:-absent}"`)

	s.thenExitCode(0)
	s.thenStdoutContains("a=value-a")
	s.thenStdoutContains("b=value-b")
	s.thenStdoutContains("c=absent")
}

func Test_FilteringEnvironment_EmptyValuePassedThrough(t *testing.T) {
	// A pass rule for a var with an empty value forwards it as an empty string, not as absent.
	s := newScenario(t)
	t.Setenv("EXECAVE_EMPTY", "")
	s.givenRules("env:pass:EXECAVE_EMPTY")

	s.whenRun("sh", "-c", `if [ -z "${EXECAVE_EMPTY+x}" ]; then echo absent; else echo "set:${EXECAVE_EMPTY}"; fi`)

	s.thenExitCode(0)
	s.thenStdoutContains("set:")
}

func Test_FilteringEnvironment_AbsentHostVarSilentlySkipped(t *testing.T) {
	// A pass rule for a var not set in the host env does not cause an error;
	// the var is simply absent inside the sandbox.
	s := newScenario(t)
	require.NoError(t, os.Unsetenv("EXECAVE_ABSENT"))
	s.givenRules("env:pass:EXECAVE_ABSENT")

	s.whenRun("sh", "-c", `echo ${EXECAVE_ABSENT:-absent}`)

	s.thenExitCode(0)
	s.thenStdoutContains("absent")
}

func Test_FilteringEnvironment_NoSandboxPassesAllVarsUnfiltered(t *testing.T) {
	// --no-sandbox mode skips env filtering: all host env vars pass through.
	s := newScenario(t)
	t.Setenv("EXECAVE_TEST_VAR", "no-sandbox-visible")
	s.givenRules()

	s.whenRunNoSandboxMonitorFile("", "sh", "-c", `echo ${EXECAVE_TEST_VAR:-absent}`)

	s.thenExitCode(0)
	s.thenStdoutContains("no-sandbox-visible")
}
