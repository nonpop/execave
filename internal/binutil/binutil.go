// Package binutil resolves, validates, and version-checks the external
// binaries that execave depends on (bwrap and strace), and detects the
// ELF interpreter for dynamic linker auto-mounting.
package binutil

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ResolveBwrap resolves "bwrap" from PATH and validates root ownership.
// Returns the absolute path or an error if not found or not root-owned.
func ResolveBwrap() (string, error) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return "", fmt.Errorf("look up path: %w", err)
	}

	if err := validateBinary(path); err != nil {
		return "", fmt.Errorf("validate binary: %w", err)
	}

	return path, nil
}

// ResolveStrace resolves "strace" from PATH and validates root ownership.
// Returns the absolute path or an error if not found or not root-owned.
func ResolveStrace() (string, error) {
	path, err := exec.LookPath("strace")
	if err != nil {
		return "", fmt.Errorf("look up path: %w", err)
	}

	if err := validateBinary(path); err != nil {
		return "", fmt.Errorf("validate binary: %w", err)
	}

	return path, nil
}

// InterpreterPath returns the dynamic linker path from the ELF binary at
// bwrapPath. Returns empty string if not determinable (static binary,
// non-ELF, read error, or non-absolute interpreter path).
func InterpreterPath(bwrapPath string) string {
	elfFile, err := elf.Open(bwrapPath)
	if err != nil {
		return ""
	}
	defer elfFile.Close() //nolint:errcheck // read-only

	for _, prog := range elfFile.Progs {
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

// validateBinary checks that the binary at path is root-owned via Lstat
// (no symlink follow). This prevents symlink-based binary substitution
// by non-privileged users.
func validateBinary(path string) error {
	linfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	lstat, ok := linfo.Sys().(*syscall.Stat_t)
	if !ok {
		panic("execave bug: OS returned unexpected file info type (expected syscall.Stat_t)")
	}
	if lstat.Uid != 0 {
		return fmt.Errorf("%s not owned by root (uid %d)", path, lstat.Uid)
	}

	return nil
}
