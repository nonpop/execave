package monitor

import (
	"io"

	"github.com/nonpop/execave/internal/accesslog"
)

// Exports for testing.

func (m *Monitor) BuildStraceArgs(tmpPath string, command []string) []string {
	return m.buildStraceArgs(tmpPath, command)
}

func (m *Monitor) ProcessStraceOutput(output io.Reader) error {
	return m.processStraceOutput(output)
}

var MapSyscallToOperation = mapSyscallToOperation

const (
	ExportedRuleNoMatch                   = accesslog.RuleNoMatch
	ExportedRuleUnresolvedRelativePath    = accesslog.RuleUnresolvedRelativePath
	ExportedRuleSymlinkTargetUnresolvable = accesslog.RuleSymlinkTargetUnresolvable
	ExportedRuleSymlinkDepthExceeded      = accesslog.RuleSymlinkDepthExceeded
)
