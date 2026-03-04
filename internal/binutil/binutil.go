// Package binutil provides external binary resolution, validation, and version checking.
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

// ResolveBwrap finds and validates the bwrap binary.
// exec.LookPath resolves "bwrap" from PATH. The resolved path entry is
// validated for root ownership before use.
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

// ResolveStrace finds and validates the strace binary.
// exec.LookPath resolves "strace" from PATH. The resolved path entry is
// validated for root ownership before use.
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

// InterpreterPath reads the PT_INTERP program header from the ELF binary at
// bwrapPath and returns the dynamic linker path. Returns empty string for
// static binaries (no PT_INTERP), non-ELF files, read errors, or non-absolute
// interpreter paths.
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

// validateBinary checks that the binary at path is safe to execute.
//
// Lstat (no symlink follow): the path entry itself must be owned by root.
// A non-privileged attacker cannot create root-owned symlinks, so this
// prevents symlink-to-real-binary injection attacks. If the path is a
// symlink to a non-root-owned file, that is the system administrator's
// responsibility.
func validateBinary(path string) error {
	linfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	lstat, ok := linfo.Sys().(*syscall.Stat_t)
	if !ok {
		panic("FileInfo.Sys() is not *syscall.Stat_t")
	}
	if lstat.Uid != 0 {
		return fmt.Errorf("%s not owned by root (uid %d)", path, lstat.Uid)
	}

	return nil
}
