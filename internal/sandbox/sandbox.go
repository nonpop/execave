// Package sandbox translates a [config.Config] into a bubblewrap (bwrap)
// command with a seccomp-bpf filter.
//
// [Prepare] is the sole entry point. It builds bwrap arguments from filesystem
// rules, creates the seccomp filter, and returns a [SandboxedCommand] ready
// for [exec.Cmd] construction. [ManagedDirs] returns the paths the sandbox
// handles automatically.
package sandbox

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/tunnel"
)

// tiocSTISysctlPath is the sysctl path for TIOCSTI legacy mode.
const tiocSTISysctlPath = "/proc/sys/dev/tty/legacy_tiocsti"

// managedDirs are directories the sandbox handles automatically.
// Includes: runtime infrastructure (/dev, /proc), isolation (/tmp),
// and bwrap's internal pivot_root directories (/newroot, /oldroot).
//
//nolint:gochecknoglobals // used read-only
var managedDirs = []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}

// ManagedDirs returns the directories the sandbox manages automatically.
// User rules must not target these paths.
func ManagedDirs() []string {
	return managedDirs
}

// sandbox manages the bubblewrap sandbox configuration and execution.
type sandbox struct {
	cfg *config.Config
}

// SandboxedCommand holds a fully prepared bwrap invocation.
type SandboxedCommand struct {
	BwrapPath    string     // Absolute path to bwrap.
	Args         []string   // Complete bwrap args (excluding binary name).
	ExtraFiles   []*os.File // Files to pass to the child (seccomp pipe).
	SetupExecves int        // Exec transitions before the user command starts.
}

// Prepare builds the bwrap command and seccomp filter.
// bwrapPath must not be empty (panics otherwise). seccompFD is the fd number
// for the seccomp pipe in the child. The returned cleanup releases resources.
func Prepare(bwrapPath string, cfg *config.Config, command []string, seccompFD int) (*SandboxedCommand, func(), error) {
	if bwrapPath == "" {
		panic("bwrapPath must not be empty")
	}
	s := &sandbox{cfg: cfg}

	bwrapArgs := s.buildBwrapArgs(command, seccompFD)

	pipe, err := seccomp.FilterPipe(allowedSyscallMap(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("create seccomp filter: %w", err)
	}

	cleanup := func() {
		_ = pipe.Close()
	}

	return &SandboxedCommand{
		BwrapPath:    bwrapPath,
		Args:         bwrapArgs,
		ExtraFiles:   []*os.File{pipe},
		SetupExecves: 2 + tunnel.ExecCount, // bwrap exec, tunnel exec, then user command exec
	}, cleanup, nil
}

// allowedSyscallMap builds a map of allowed syscall names from cfg.SyscallRules,
func allowedSyscallMap(cfg *config.Config) map[string]bool {
	m := make(map[string]bool, len(cfg.SyscallRules))
	for _, rule := range cfg.SyscallRules {
		m[rule.Name] = true
	}
	return m
}

// tiocSTIBlocked reports whether the kernel blocks TIOCSTI terminal injection.
// Returns true only when sysctl at path contains "0" (TIOCSTI disabled).
// Returns false for all other cases: sysctl contains non-zero value, file absent, or unreadable.
// This fail-safe default ensures --new-session is used when kernel status is unknown.
func tiocSTIBlocked(sysctlPath string) bool {
	data, err := os.ReadFile(sysctlPath) //#nosec G304 -- sysctlPath is a hardcoded constant, not user input
	if err != nil {
		// File absent (pre-6.2 kernel) or unreadable - assume TIOCSTI enabled
		return false
	}

	content := strings.TrimSpace(string(data))
	return content == "0"
}

// buildBwrapArgs constructs bwrap arguments from the sandbox configuration.
// seccompFD is the file descriptor number for the seccomp pipe.
func (s *sandbox) buildBwrapArgs(command []string, seccompFD int) []string {
	args := []string{}

	// Unshare all namespaces (PID, IPC, UTS, network, cgroup) for process isolation.
	args = append(args, "--unshare-all")

	// Create new session to prevent TIOCSTI terminal injection attacks (CVE-2017-5226).
	// Skip on modern kernels (6.2+) where TIOCSTI is already blocked by the kernel.
	// This allows SIGWINCH delivery for TUI applications while maintaining security.
	if !tiocSTIBlocked(tiocSTISysctlPath) {
		args = append(args, "--new-session")
	}

	// Environment variables pass through from host (no --clearenv)

	// Note: No --chdir flag. The sandboxed process inherits host cwd.
	// If cwd is not mounted, bwrap falls back to $HOME, or / if $HOME is also not mounted.

	args = append(args, "--die-with-parent")

	args = append(args, "--dev", "/dev")
	args = append(args, "--proc", "/proc")
	args = append(args, "--tmpfs", "/tmp")

	args = s.addRuleMounts(args)

	args = append(args, "--seccomp", strconv.Itoa(seccompFD))
	args = append(args, "--")
	args = append(args, command...)

	return args
}

// addRuleMounts adds bind mounts for config rules.
func (s *sandbox) addRuleMounts(args []string) []string {
	mounted := make(map[string]bool)
	rules := s.getSortedRules()

	for _, rule := range rules {
		path := rule.Path

		if mounted[path] {
			panic("duplicate mount path: " + path)
		}

		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "execave: skipping rule %q: %v\n", rule.RawRule, err)
			continue
		}

		args = appendMountArgs(args, rule, info, rules)
		mounted[path] = true
	}

	return args
}

func (s *sandbox) getSortedRules() []fsrules.Rule {
	sorted := make([]fsrules.Rule, len(s.cfg.FSRules))
	copy(sorted, s.cfg.FSRules)
	// Sort by shortest path first (parents before children).
	// In bwrap, later mounts overlay earlier ones, so children with
	// different permissions must come after their parents.
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Path) < len(sorted[j].Path) })
	return sorted
}

// hasChildRules reports whether any rule's path is a strict descendant of parentPath.
func hasChildRules(rules []fsrules.Rule, parentPath string) bool {
	prefix := parentPath + "/"
	for _, r := range rules {
		if strings.HasPrefix(r.Path, prefix) {
			return true
		}
	}
	return false
}

// appendMountArgs adds bwrap arguments for a single rule.
// rules is the full set of rules, used to determine chmod for fs:none directories.
func appendMountArgs(args []string, rule fsrules.Rule, info os.FileInfo, rules []fsrules.Rule) []string {
	path := rule.Path

	switch rule.Permission {
	case fsrules.PermissionReadWrite:
		return append(args, "--bind", path, path)

	case fsrules.PermissionReadOnly:
		return append(args, "--ro-bind", path, path)

	case fsrules.PermissionNone:
		// Block access by overlaying with inaccessible content.
		// For directories: empty tmpfs hides original contents.
		// For files: /dev/null returns Permission denied.
		if info.IsDir() {
			args = append(args, "--tmpfs", path)
			// Restrict permissions on the tmpfs mount. Without this, the empty
			// tmpfs would be world-readable/writable (0755), which contradicts
			// the guarantee that fs:none paths are inaccessible.
			// Dirs with child rules get 0111 (execute-only) to allow path
			// traversal to child mounts. Dirs without children get 0000
			// (completely blocked).
			if hasChildRules(rules, path) {
				return append(args, "--chmod", "0111", path)
			}
			return append(args, "--chmod", "0000", path)
		}
		return append(args, "--bind", "/dev/null", path)

	case fsrules.PermissionUnknown:
		panic("rule has PermissionUnknown: " + rule.RawRule)
	}

	return args
}
