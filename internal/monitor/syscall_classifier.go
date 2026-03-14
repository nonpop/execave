package monitor

import (
	"strings"
)

// operationType classifies filesystem operations as read or write.
type operationType string

const (
	// operationIgnored indicates a syscall we intentionally ignore.
	operationIgnored operationType = "IGNORED"
	// operationRead represents read operations (stat, open for read, etc).
	operationRead operationType = "READ"
	// operationWrite represents write operations (write, unlink, mkdir, etc).
	operationWrite operationType = "WRITE"
)

func mapSyscallToOperation(syscall string, line string) operationType {
	// Handle open/openat specially - operation depends on flags
	if syscall == "open" || syscall == "openat" {
		return classifyOpenOperation(line)
	}

	if op, ok := syscallOperationMap[syscall]; ok {
		return op
	}

	if ignoredSyscalls[syscall] {
		return operationIgnored
	}

	// Unknown syscall - could indicate a new kernel syscall we should handle.
	panic("execave bug: unrecognized syscall in strace output: " + syscall)
}

// syscallOperationMap maps syscalls to read or write operations.
//
//nolint:gochecknoglobals // package-private, used read-only
var syscallOperationMap = map[string]operationType{
	// Read operations
	"stat": operationRead, "lstat": operationRead, "fstat": operationRead,
	"fstatat": operationRead, "newfstatat": operationRead, "statx": operationRead,
	"read": operationRead, "readv": operationRead, "pread": operationRead,
	"pread64":    operationRead,
	"readdir":    operationRead,
	"getdents":   operationRead,
	"getdents64": operationRead,
	"readlink":   operationRead, "readlinkat": operationRead,
	"access": operationRead, "faccessat": operationRead, "faccessat2": operationRead,
	"execve": operationRead, "execveat": operationRead,

	// Write operations
	"write": operationWrite, "writev": operationWrite, "pwrite": operationWrite,
	"pwrite64":  operationWrite,
	"unlink":    operationWrite,
	"unlinkat":  operationWrite,
	"rmdir":     operationWrite,
	"mkdir":     operationWrite,
	"mkdirat":   operationWrite,
	"rename":    operationWrite,
	"renameat":  operationWrite,
	"renameat2": operationWrite,
	"truncate":  operationWrite, "ftruncate": operationWrite,
	"chmod": operationWrite, "fchmod": operationWrite, "fchmodat": operationWrite,
	"chown": operationWrite, "fchown": operationWrite, "lchown": operationWrite,
	"fchownat": operationWrite,
	"link":     operationWrite, "linkat": operationWrite, "symlink": operationWrite,
	"symlinkat": operationWrite,
	"creat":     operationWrite,
}

// ignoredSyscalls lists syscalls from "trace=file" that we intentionally don't log.
// These don't represent meaningful filesystem access for our purposes.
//
//nolint:gochecknoglobals // package-private, used read-only
var ignoredSyscalls = map[string]bool{
	// Directory operations (don't access file contents)
	"chdir": true, "fchdir": true, "getcwd": true,
	// File descriptor operations (fd already opened, path not visible)
	"close": true, "dup": true, "dup2": true, "dup3": true, "fcntl": true,
	// Filesystem metadata (not file access)
	"statfs": true, "fstatfs": true, "ustat": true,
	// Mount/namespace operations (used by bwrap for sandbox setup, not user access)
	"mount": true, "umount": true, "umount2": true,
	"pivot_root": true, "chroot": true,
	"unshare": true, "setns": true, "clone": true, "clone3": true,
	"prctl": true,
	// Extended attributes (TODO: may want to track these)
	"getxattr": true, "lgetxattr": true, "fgetxattr": true,
	"setxattr": true, "lsetxattr": true, "fsetxattr": true,
	"listxattr": true, "llistxattr": true, "flistxattr": true,
	"removexattr": true, "lremovexattr": true, "fremovexattr": true,
	// Timestamps (minor metadata, already covered by chmod/chown)
	"utime": true, "utimes": true, "utimensat": true, "futimesat": true,
	// Watch/notify (doesn't access content)
	"inotify_add_watch": true, "fanotify_mark": true,
	// Handle-based (rare, path not directly visible)
	"name_to_handle_at": true, "open_by_handle_at": true,
}

func classifyOpenOperation(line string) operationType {
	// Flags appear after the path argument. Find the path's closing quote
	// to avoid matching flag names that appear in filenames.
	// Strace format: open("/path", O_RDONLY) or openat(fd, "/path", O_CREAT|O_WRONLY)
	lastQuote := strings.LastIndex(line, "\"")
	if lastQuote == -1 {
		panic("execave bug: open/openat strace line has no quoted path: " + line)
	}

	flagsPart := line[lastQuote+1:]
	if strings.Contains(flagsPart, "O_WRONLY") || strings.Contains(flagsPart, "O_RDWR") || strings.Contains(flagsPart, "O_CREAT") {
		return operationWrite
	}
	return operationRead
}
