// Package sandbox executes commands in a bubblewrap container with restricted filesystem access.
package sandbox

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/seccomp"
)

// tiocSTISysctlPath is the sysctl path for TIOCSTI legacy mode.
const tiocSTISysctlPath = "/proc/sys/dev/tty/legacy_tiocsti"

// ManagedDirs are directories the sandbox handles automatically.
// Includes: runtime infrastructure (/dev, /proc), isolation (/tmp),
// and bwrap's internal pivot_root directories (/newroot, /oldroot).
//
//nolint:gochecknoglobals // used read-only
var ManagedDirs = []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}

// InterpreterPath reads the PT_INTERP program header from the ELF binary at
// bwrapPath and returns the dynamic linker path. Returns empty string for
// static binaries (no PT_INTERP), non-ELF files, read errors, or non-absolute
// interpreter paths.
func InterpreterPath(bwrapPath string) string {
	f, err := elf.Open(bwrapPath)
	if err != nil {
		return ""
	}
	defer f.Close() //nolint:errcheck // read-only

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			data := make([]byte, prog.Filesz)
			_, err := prog.ReadAt(data, 0)
			if err != nil {
				return ""
			}
			// PT_INTERP is a null-terminated string
			path := strings.TrimRight(string(data), "\x00")
			if !filepath.IsAbs(path) {
				return ""
			}
			return path
		}
	}
	return ""
}

// ManagedPathsWith returns ManagedDirs extended with interpreterPath if non-empty.
// Returns ManagedDirs as-is when interpreterPath is empty.
func ManagedPathsWith(interpreterPath string) []string {
	if interpreterPath == "" {
		return ManagedDirs
	}
	paths := make([]string, len(ManagedDirs)+1)
	copy(paths, ManagedDirs)
	paths[len(ManagedDirs)] = interpreterPath
	return paths
}

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

// InsertSeccompArg inserts --seccomp <fd> before the -- separator in bwrap args.
// args must contain "--" as a separator. fd is the file descriptor number of
// the seccomp filter pipe (e.g. 3 for the direct path, 4 for the monitored path).
func InsertSeccompArg(args []string, fd int) []string {
	for i, a := range args {
		if a == "--" {
			seccompArgs := []string{"--seccomp", strconv.Itoa(fd)}
			result := make([]string, 0, len(args)+len(seccompArgs))
			result = append(result, args[:i]...)
			result = append(result, seccompArgs...)
			result = append(result, args[i:]...)
			return result
		}
	}
	panic("internal error: InsertSeccompArg: no -- separator found in bwrap args")
}

// HasNetworkPath reports whether the sandbox has network proxy-tunnel configuration.
func (s *Sandbox) HasNetworkPath() bool {
	return s.netPath != nil
}

// ResolveBwrap finds and validates the bwrap binary.
// exec.LookPath resolves "bwrap" from PATH. The resolved path is validated
// for root ownership and safe permissions before use.
func ResolveBwrap() (string, error) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return "", fmt.Errorf("resolve bwrap: bubblewrap (bwrap) not found in PATH: %w", err)
	}

	if err := ValidateBinary(path); err != nil {
		return "", fmt.Errorf("resolve bwrap: %w", err)
	}

	return path, nil
}

// ResolveStrace finds and validates the strace binary.
// exec.LookPath resolves "strace" from PATH. The resolved path is validated
// for root ownership and safe permissions before use.
func ResolveStrace() (string, error) {
	path, err := exec.LookPath("strace")
	if err != nil {
		return "", fmt.Errorf("resolve strace: strace not found in PATH: %w", err)
	}

	if err := ValidateBinary(path); err != nil {
		return "", fmt.Errorf("resolve strace: %w", err)
	}

	return path, nil
}

// ValidateBinary checks that the binary at path is safe to execute.
//
// Two checks are performed:
//  1. Lstat (no symlink follow): the path entry itself must be owned by root.
//     A non-privileged attacker cannot create root-owned symlinks, so this
//     prevents symlink-to-real-binary injection attacks.
//  2. Stat (follows symlinks): the resolved target must be owned by root and
//     not writable by group or others. Symlink permission bits are always 0777
//     (meaningless), so we must follow symlinks to check actual file permissions.
func ValidateBinary(path string) error {
	// Lstat: check the path entry itself (not following symlinks).
	linfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("validate binary: lstat %s: %w", path, err)
	}
	lstat, ok := linfo.Sys().(*syscall.Stat_t)
	if !ok {
		panic("validate binary: Stat_t cast failed (non-Linux?)")
	}
	if lstat.Uid != 0 {
		return fmt.Errorf("validate binary: %s not owned by root (uid %d)", path, lstat.Uid)
	}

	// Stat: check the resolved target for write-bit safety.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("validate binary: stat %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		panic("validate binary: Stat_t cast failed (non-Linux?)")
	}
	if stat.Uid != 0 {
		return fmt.Errorf("validate binary: %s resolved target not owned by root (uid %d)", path, stat.Uid)
	}
	const groupOrOtherWritable = 0o022
	if stat.Mode&groupOrOtherWritable != 0 {
		return fmt.Errorf("validate binary: %s writable by group or others (mode %04o)", path, stat.Mode)
	}

	return nil
}

// Run executes a command in the sandbox and returns its exit code.
func (s *Sandbox) Run(ctx context.Context, command []string) (int, error) {
	if len(command) == 0 {
		return 1, errors.New("no command specified")
	}

	bwrapPath, err := ResolveBwrap()
	if err != nil {
		return 1, err
	}

	bwrapArgs := s.BuildBwrapArgs(command)

	var allowedSyscalls map[string]bool
	if len(s.cfg.SyscallAllowRules) > 0 {
		allowedSyscalls = make(map[string]bool, len(s.cfg.SyscallAllowRules))
		for _, name := range s.cfg.SyscallAllowRules {
			allowedSyscalls[name] = true
		}
	}

	var extraFiles []*os.File
	pipe, err := seccomp.FilterPipe(allowedSyscalls)
	if err != nil {
		return 1, fmt.Errorf("create seccomp filter: %w", err)
	}
	defer pipe.Close() //nolint:errcheck // pipe closed after cmd.Run
	extraFiles = []*os.File{pipe}
	bwrapArgs = InsertSeccompArg(bwrapArgs, 3)

	cmd := exec.CommandContext(ctx, bwrapPath, bwrapArgs...) // #nosec G204 -- args built from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = extraFiles

	err = cmd.Run()
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

// BuildBwrapArgs constructs bwrap arguments (exported for monitor integration).
func (s *Sandbox) BuildBwrapArgs(command []string) []string {
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
	// If cwd is not mounted, bwrap falls back to /.
	args = append(args, "--die-with-parent")

	args = append(args, "--dev", "/dev")
	args = append(args, "--proc", "/proc")
	args = append(args, "--tmpfs", "/tmp")

	// Auto-mount the ELF interpreter (dynamic linker) so dynamically linked
	// binaries can load. Without this, the kernel can't start the process.
	if s.cfg.InterpreterPath != "" {
		args = append(args, "--ro-bind", s.cfg.InterpreterPath, s.cfg.InterpreterPath)
	}

	writableConfig := false
	if s.configPath != "" {
		resolver := fsrules.NewAccessResolver(s.cfg.FSRules, s.cfg.ManagedPaths)
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
		syntheticRule := fsrules.AccessRule{
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

func (s *Sandbox) getSortedRules() []fsrules.AccessRule {
	sorted := make([]fsrules.AccessRule, len(s.cfg.FSRules))
	copy(sorted, s.cfg.FSRules)
	// Sort by shortest path first (parents before children).
	// In bwrap, later mounts overlay earlier ones, so children with
	// different permissions must come after their parents.
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Path) < len(sorted[j].Path) })
	return sorted
}

// hasChildRules reports whether any rule's path is a strict descendant of parentPath.
func hasChildRules(rules []fsrules.AccessRule, parentPath string) bool {
	prefix := parentPath + "/"
	for _, r := range rules {
		if strings.HasPrefix(r.Path, prefix) {
			return true
		}
	}
	return false
}

// appendMountArgs adds bwrap arguments for a single rule.
func appendMountArgs(args []string, rule fsrules.AccessRule, info os.FileInfo) []string {
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
