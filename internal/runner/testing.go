package runner

import (
	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/sandbox"
)

// NewTestRunner creates a runner for testing with minimal configuration.
// The runner is in idle state by default.
func NewTestRunner() *Runner {
	cfg := &config.Config{
		FSRules:           nil,
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	return New(cfg, "/tmp/test-config.json", &sandbox.NetworkPath{UDSPath: "", ExecaveBinary: ""})
}

// SetTestStatus sets the runner's status for testing purposes.
// This is only for use in tests to simulate different run states.
//
// IMPORTANT: This is a test-only method and should never be used in production code.
func (r *Runner) SetTestStatus(status RunStatus) {
	r.mu.Lock()
	r.status = status
	r.mu.Unlock()
	r.notifyStatus()
}

// SetTestLogger sets the runner's logger for testing purposes.
// This is only for use in tests to inject a logger without calling Start.
//
// IMPORTANT: This is a test-only method and should never be used in production code.
func (r *Runner) SetTestLogger(logger *accesslog.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logger = logger
}
