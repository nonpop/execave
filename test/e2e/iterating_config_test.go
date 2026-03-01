package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestE2E_IteratingConfig_EditConfigAndReRunWithMonitor tests that after reviewing
// monitor output, updating rules and re-running applies the new policy.
func TestE2E_IteratingConfig_EditConfigAndReRunWithMonitor(t *testing.T) {
	s := newScenario(t)
	workspace := s.givenDir("workspace")
	secret := s.givenDir("secret")
	secretFile := secret.file("secret.txt", "secret")

	s.givenRules(
		"fs:ro:/usr/lib",
		"fs:rw:"+workspace.String(),
	)

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", "ls /usr/lib >/dev/null && cat "+secretFile+" >/dev/null || true")

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", secret.rel("secret.txt"), "DENY")

	s.givenRules(
		"fs:ro:/usr/lib",
		"fs:rw:"+workspace.String(),
		"fs:ro:"+secret.String(),
	)

	s.whenRunTextLogWithFlags([]string{"--show-allowed"},
		"sh", "-c", "ls /usr/lib >/dev/null && cat "+secretFile+" >/dev/null")

	s.thenExitCode(0)
	s.thenStderrHasEntry("READ", secret.rel("secret.txt"), "OK", "fs:ro:"+secret.String())
}

// TestE2E_IteratingConfig_InvalidConfigRejectedOnStart tests that invalid rules are
// rejected before sandbox start and command execution.
func TestE2E_IteratingConfig_InvalidConfigRejectedOnStart(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:invalid")

	s.whenRunTextLog("-", "sh", "-c", "echo SHOULD_NOT_RUN")

	s.thenExitCode(1)
	s.thenStderrContains("malformed rule")
	s.thenStderrNotContains("READ")
	s.thenStderrNotContains("DENY")
	assert.Empty(t, s.lastResult.Stdout)
}
