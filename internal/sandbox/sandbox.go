// Package sandbox executes commands in a bubblewrap container with restricted filesystem access.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
)

// ManagedDirs are directories the sandbox handles automatically.
// Includes: runtime infrastructure (/dev, /proc), isolation (/tmp),
// and bwrap's internal pivot_root directories (/newroot, /oldroot).
//
//nolint:gochecknoglobals // used read-only
var ManagedDirs = []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}

const (
	// sandboxUDSPath is the fixed path where the proxy UDS is mounted inside the sandbox.
	sandboxUDSPath = "/tmp/execave-proxy.sock"
	// sandboxExecavePath is the fixed path where the execave binary is mounted inside the sandbox.
	sandboxExecavePath = "/tmp/execave"
)

// NetworkPath holds paths for proxy-tunnel network setup.
// When non-nil, the sandbox bind-mounts the UDS and execave binary,
// and wraps the user command with the network tunnel.
type NetworkPath struct {
	// UDSPath is the host-side path to the proxy Unix domain socket.
	UDSPath string
	// ExecaveBinary is the host-side path to the execave binary.
	ExecaveBinary string
}

// Sandbox manages the bubblewrap sandbox configuration and execution.
type Sandbox struct {
	cfg        *config.Config
	configPath string
	netPath    *NetworkPath
}

// New creates a new Sandbox.
// configPath must be empty or absolute.
// netPath may be nil when no net rules are configured.
func New(cfg *config.Config, configPath string, netPath *NetworkPath) *Sandbox {
	if configPath != "" && !filepath.IsAbs(configPath) {
		panic("internal error: configPath must be absolute: " + configPath)
	}
	return &Sandbox{
		cfg:        cfg,
		configPath: configPath,
		netPath:    netPath,
	}
}

// HasNetworkPath reports whether the sandbox has network proxy-tunnel configuration.
func (s *Sandbox) HasNetworkPath() bool {
	return s.netPath != nil
}

// Run executes a command in the sandbox and returns its exit code.
func (s *Sandbox) Run(ctx context.Context, command []string) (int, error) {
	if len(command) == 0 {
		return 1, errors.New("no command specified")
	}

	if _, err := exec.LookPath("bwrap"); err != nil {
		return 1, fmt.Errorf("bubblewrap (bwrap) not found in PATH: %w", err)
	}

	bwrapArgs := s.BuildBwrapArgs(command)

	cmd := exec.CommandContext(ctx, "bwrap", bwrapArgs...) // #nosec G204 -- args built from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		exitErr := new(exec.ExitError)
		if errors.As(err, &exitErr) {
			// Command ran but exited with non-zero code or signal
			ws, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok && ws.Signaled() {
				// Process was terminated by signal - return 128 + signal number
				// This matches shell convention (e.g., SIGINT = 2 → exit code 130)
				return 128 + int(ws.Signal()), nil //nolint: mnd // well-known code
			}
			return exitErr.ExitCode(), nil
		}
		// Failed to execute bwrap itself
		return 1, fmt.Errorf("execute bwrap: %w", err)
	}

	return 0, nil
}

// BuildBwrapArgs constructs bwrap arguments (exported for monitor integration).
func (s *Sandbox) BuildBwrapArgs(command []string) []string {
	args := []string{}

	// Unshare all namespaces (PID, IPC, UTS, network, cgroup) for process isolation.
	args = append(args, "--unshare-all")

	// Create new session to prevent TIOCSTI terminal injection attacks (CVE-2017-5226).
	args = append(args, "--new-session")

	// Environment variables pass through from host (no --clearenv)

	// Note: No --chdir flag. The sandboxed process inherits host cwd.
	// If cwd is not mounted, bwrap falls back to /.
	args = append(args, "--die-with-parent")

	args = append(args, "--dev", "/dev")
	args = append(args, "--proc", "/proc")
	args = append(args, "--tmpfs", "/tmp")

	writableConfig := false
	if s.configPath != "" {
		resolver := fsrules.NewResolver(s.cfg.FSRules, s.cfg.ManagedPaths)
		accessLevel := resolver.PermissionFor(s.configPath)
		if accessLevel <= fsrules.PermissionReadWrite {
			writableConfig = true
			fmt.Fprintln(os.Stderr, "execave: config file forced read-only")
		}
	}

	args = s.addRuleMounts(args, writableConfig)

	// When net rules are present, bind-mount the proxy UDS and execave binary,
	// then wrap the user command with the network tunnel.
	if s.netPath != nil {
		args = append(args, "--ro-bind", s.netPath.UDSPath, sandboxUDSPath)
		args = append(args, "--ro-bind", s.netPath.ExecaveBinary, sandboxExecavePath)

		args = append(args, "--")
		args = append(args, sandboxExecavePath, "network-tunnel", sandboxUDSPath, "--")
		args = append(args, command...)
	} else {
		args = append(args, "--")
		args = append(args, command...)
	}

	return args
}

// addRuleMounts adds bind mounts for config rules.
// If writableConfig, forces config file read-only.
func (s *Sandbox) addRuleMounts(args []string, writableConfig bool) []string {
	mounted := make(map[string]bool)
	rules := s.getSortedRules()

	if writableConfig {
		syntheticRule := fsrules.Rule{
			Resource:   fsrules.ResourceFS,
			Permission: fsrules.PermissionReadOnly,
			Path:       s.configPath,
			RawRule:    "fs:ro:" + s.configPath,
		}
		// Append so it comes after parent directory (overlays with ro permission)
		rules = append(rules, syntheticRule)
	}

	for _, rule := range rules {
		path := rule.Path

		if mounted[path] {
			panic("internal error: duplicate mount path: " + path)
		}

		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "execave: skipping rule %q: %v\n", rule.RawRule, err)
			continue
		}

		args = appendMountArgs(args, rule, info)
		mounted[path] = true

		// Restrict permissions on fs:none directory tmpfs mounts.
		// Without this, the empty tmpfs would be world-readable/writable (0755),
		// which contradicts the guarantee that fs:none paths are inaccessible.
		// Dirs with child rules get 0111 (execute-only) to allow path traversal
		// to child mounts. Dirs without children get 0000 (completely blocked).
		if rule.Permission == fsrules.PermissionNone && info.IsDir() {
			if hasChildRules(rules, path) {
				args = append(args, "--chmod", "0111", path)
			} else {
				args = append(args, "--chmod", "0000", path)
			}
		}
	}

	return args
}

func (s *Sandbox) getSortedRules() []fsrules.Rule {
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
func appendMountArgs(args []string, rule fsrules.Rule, info os.FileInfo) []string {
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
			return append(args, "--tmpfs", path)
		}
		return append(args, "--bind", "/dev/null", path)

	case fsrules.PermissionUnknown:
		panic("internal error: rule has PermissionUnknown: " + rule.RawRule)
	}

	return args
}
