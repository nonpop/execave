package logfilter

import (
	"fmt"
	"net"
	"strconv"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
)

// IsNolog reports whether entry matches a nolog rule, meaning it should be
// hidden when nolog filtering is enabled.
// fsRes, netRes, and syscallNolog may be nil (meaning no log rules — all entries are visible).
func IsNolog(entry accesslog.Entry, fsRes *fsrules.LogResolver, netRes *netrules.LogResolver, syscallNolog map[string]bool) bool {
	switch entry.Operation {
	case accesslog.OperationRead, accesslog.OperationWrite:
		if fsRes == nil {
			return false
		}
		return !fsRes.Visible(entry.Target)
	case accesslog.OperationHTTP:
		if netRes == nil {
			return false
		}
		host, portStr, err := net.SplitHostPort(entry.Target)
		if err != nil {
			return false
		}
		portNum, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return false
		}
		return !netRes.Visible(host, uint16(portNum))
	case accesslog.OperationSyscall:
		return syscallNolog[entry.Target]
	default:
		panic(fmt.Sprintf("IsNolog: unexpected operation type %q", entry.Operation))
	}
}
