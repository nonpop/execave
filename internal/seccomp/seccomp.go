// Package seccomp builds cBPF deny-list filters for bwrap's --seccomp flag.
//
// The blocked set has two sub-categories: ruleable syscalls (selectively
// re-enabled via config) and defense-in-depth syscalls (already prevented
// by the user-namespace model). See [RuleableSyscallNames] and [FilterPipe].
//
// Only x86_64 and arm64 are supported; [FilterPipe] panics on other architectures.
package seccomp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// BPF opcode constants for classic BPF programs.
const (
	bpfLdWAbs  uint16 = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJmpJeqK uint16 = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRetK    uint16 = 0x06 // BPF_RET | BPF_K
)

// Offsets into the seccomp_data structure passed to BPF programs.
const (
	seccompDataOffsetNr   uint32 = 0 // syscall number
	seccompDataOffsetArch uint32 = 4 // CPU architecture
)

// blockedSyscall pairs a kernel syscall name with its number.
// When defenseOnly is true, the syscall is blocked as defense-in-depth only:
// the kernel already prevents it inside bwrap's user-namespace sandbox
// (e.g., requires init-namespace capabilities or is removed from the kernel),
// so it cannot be meaningfully allowed via config rules.
type blockedSyscall struct {
	name        string
	nr          uint32
	defenseOnly bool
}

// blockedSyscalls lists the dangerous syscalls to deny.
// These span kernel modules, BPF, ptrace, io_uring, namespace manipulation,
// mount, keyring, time manipulation, and system control.
//
// Syscalls marked defenseOnly require init-namespace capabilities that bwrap's
// user-namespace sandbox drops, or are removed from the kernel entirely. The
// kernel already prevents them, so allowing them via config rules is pointless.
// They remain in the BPF filter as defense-in-depth in case the sandbox model
// changes.
//
//nolint:gochecknoglobals // package private read-only variable
var blockedSyscalls = []blockedSyscall{
	// Ruleable syscalls — can be allowed via syscall:allow config rules.
	{"ptrace", unix.SYS_PTRACE, false},
	{"bpf", unix.SYS_BPF, false},
	{"io_uring_setup", unix.SYS_IO_URING_SETUP, false},
	{"io_uring_enter", unix.SYS_IO_URING_ENTER, false},
	{"io_uring_register", unix.SYS_IO_URING_REGISTER, false},
	{"mount", unix.SYS_MOUNT, false},
	{"umount2", unix.SYS_UMOUNT2, false},
	{"unshare", unix.SYS_UNSHARE, false},
	{"setns", unix.SYS_SETNS, false},
	{"pivot_root", unix.SYS_PIVOT_ROOT, false},
	{"chroot", unix.SYS_CHROOT, false},
	{"open_tree", unix.SYS_OPEN_TREE, false},
	{"move_mount", unix.SYS_MOVE_MOUNT, false},
	{"fsopen", unix.SYS_FSOPEN, false},
	{"fsconfig", unix.SYS_FSCONFIG, false},
	{"fsmount", unix.SYS_FSMOUNT, false},
	{"fspick", unix.SYS_FSPICK, false},
	{"keyctl", unix.SYS_KEYCTL, false},
	{"add_key", unix.SYS_ADD_KEY, false},
	{"request_key", unix.SYS_REQUEST_KEY, false},
	{"reboot", unix.SYS_REBOOT, false},

	// Defense-in-depth syscalls — the kernel already prevents these inside
	// bwrap's user-namespace sandbox. They cannot be meaningfully allowed.
	{"kexec_load", unix.SYS_KEXEC_LOAD, true},           // CAP_SYS_BOOT (init ns)
	{"kexec_file_load", unix.SYS_KEXEC_FILE_LOAD, true}, // CAP_SYS_BOOT (init ns)
	{"init_module", unix.SYS_INIT_MODULE, true},         // CAP_SYS_MODULE (init ns)
	{"finit_module", unix.SYS_FINIT_MODULE, true},       // CAP_SYS_MODULE (init ns)
	{"delete_module", unix.SYS_DELETE_MODULE, true},     // CAP_SYS_MODULE (init ns)
	{"settimeofday", unix.SYS_SETTIMEOFDAY, true},       // CAP_SYS_TIME (init ns)
	{"adjtimex", unix.SYS_ADJTIMEX, true},               // CAP_SYS_TIME (init ns)
	{"clock_adjtime", unix.SYS_CLOCK_ADJTIME, true},     // CAP_SYS_TIME (init ns)
	{"syslog", unix.SYS_SYSLOG, true},                   // CAP_SYSLOG (init ns)
	{"acct", unix.SYS_ACCT, true},                       // CAP_SYS_PACCT (init ns)
	{"swapon", unix.SYS_SWAPON, true},                   // CAP_SYS_ADMIN (init ns)
	{"swapoff", unix.SYS_SWAPOFF, true},                 // CAP_SYS_ADMIN (init ns)
	{"nfsservctl", unix.SYS_NFSSERVCTL, true},           // always ENOSYS (removed since Linux 3.1)
}

// auditArch returns the AUDIT_ARCH_* constant for the current compile-time architecture.
// Panics on unsupported architectures — execave is Linux/amd64 or Linux/arm64 only.
func auditArch() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	default:
		panic("execave does not support architecture " + runtime.GOARCH + " (only amd64 and arm64)")
	}
}

// RuleableSyscallNames returns the names of blocked syscalls that can be
// selectively re-enabled via "allow:name" config rules. Defense-in-depth
// syscalls are excluded.
func RuleableSyscallNames() []string {
	names := make([]string, 0, len(blockedSyscalls))
	for _, sc := range blockedSyscalls {
		if !sc.defenseOnly {
			names = append(names, sc.name)
		}
	}
	return names
}

// extractNrs returns the syscall numbers from a blockedSyscall slice.
func extractNrs(syscalls []blockedSyscall) []uint32 {
	nrs := make([]uint32, len(syscalls))
	for i, sc := range syscalls {
		nrs[i] = sc.nr
	}
	return nrs
}

// FilterPipe creates a pipe containing the compiled BPF deny-list filter.
// Syscalls in allowed are removed from the deny list. Pass the returned
// file's descriptor to bwrap via --seccomp. The caller must close the file.
func FilterPipe(allowed map[string]bool) (*os.File, error) {
	effective := make([]blockedSyscall, 0, len(blockedSyscalls))
	for _, sc := range blockedSyscalls {
		if !allowed[sc.name] {
			effective = append(effective, sc)
		}
	}
	data := filterFromNrs(extractNrs(effective))
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create seccomp filter pipe: %w", err)
	}
	if _, err := pipeWrite.Write(data); err != nil {
		_ = pipeRead.Close()
		_ = pipeWrite.Close()
		return nil, fmt.Errorf("write seccomp filter to pipe: %w", err)
	}
	if err := pipeWrite.Close(); err != nil {
		_ = pipeRead.Close()
		return nil, fmt.Errorf("close seccomp filter pipe write end: %w", err)
	}
	return pipeRead, nil
}

// filterFromNrs compiles a BPF deny-list filter from raw syscall numbers.
func filterFromNrs(nrs []uint32) []byte {
	insns := buildFilter(nrs, auditArch())
	var buf bytes.Buffer
	for _, insn := range insns {
		if err := binary.Write(&buf, binary.NativeEndian, insn); err != nil {
			// bytes.Buffer never returns write errors; SockFilter is a fixed-size struct.
			panic("execave bug: failed to serialize seccomp BPF instruction: " + err.Error())
		}
	}
	return buf.Bytes()
}

// buildFilter constructs the BPF program as a slice of SockFilter instructions.
// blocked contains the syscall numbers to deny; arch is the AUDIT_ARCH_* constant.
//
// The filter structure:
//
//	[0]       LD  seccomp_data.arch
//	[1]       JEQ auditArch → [2]; else → KILL
//	[2]       LD  seccomp_data.nr
//	[3..3+N-1] JEQ each blocked syscall → DENY
//	[3+N]     RET SECCOMP_RET_ALLOW
//	[3+N+1]   RET SECCOMP_RET_ERRNO|EPERM
//	[3+N+2]   RET SECCOMP_RET_KILL_PROCESS
func buildFilter(blocked []uint32, arch uint32) []unix.SockFilter {
	n := len(blocked)
	// filterOverhead: 1 LD-arch + 1 JEQ-arch + 1 LD-nr + 1 ALLOW + 1 DENY + 1 KILL
	const filterOverhead = 6
	insns := make([]unix.SockFilter, 0, n+filterOverhead)

	// [0] Load seccomp_data.arch
	insns = append(insns, unix.SockFilter{Code: bpfLdWAbs, K: seccompDataOffsetArch})

	// [1] Check architecture: match → fall through to [2]; mismatch → jump to KILL at [n+5].
	// jf offset is from the next instruction [2]: target [n+5], distance n+5-2 = n+3.
	insns = append(insns, unix.SockFilter{
		Code: bpfJmpJeqK,
		Jt:   0,
		Jf:   uint8(n + 3), // #nosec G115 -- n is bounded by len(blockedSyscalls) ≤ 253
		K:    arch,
	})

	// [2] Load seccomp_data.nr (syscall number)
	insns = append(insns, unix.SockFilter{Code: bpfLdWAbs, K: seccompDataOffsetNr})

	// [3..3+n-1] Check each blocked syscall: match → jump to DENY; no match → fall through.
	// DENY is at [3+n+1]. From instruction [3+j], next is [4+j]; jt = (3+n+1)-(4+j) = n-j.
	for j, nr := range blocked {
		insns = append(insns, unix.SockFilter{
			Code: bpfJmpJeqK,
			Jt:   uint8(n - j), // #nosec G115 -- j < n, so n-j ≥ 1; fits in uint8
			Jf:   0,
			K:    nr,
		})
	}

	// [3+n] Allow: syscall was not blocked.
	insns = append(insns, unix.SockFilter{Code: bpfRetK, K: unix.SECCOMP_RET_ALLOW})

	// [3+n+1] Deny: return EPERM for blocked syscalls.
	insns = append(insns, unix.SockFilter{Code: bpfRetK, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}) // # nosec -- EPERM=1, always fits

	// [3+n+2] Kill: wrong architecture — kill the entire process group.
	insns = append(insns, unix.SockFilter{Code: bpfRetK, K: unix.SECCOMP_RET_KILL_PROCESS})

	return insns
}
