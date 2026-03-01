package e2e_test

import (
	"testing"
)

// TestE2E_RestrictingSyscalls_DangerousSyscallsBlockedByDefault tests that
// blocked syscalls return EPERM by default while normal syscalls work.
func TestE2E_RestrictingSyscalls_DangerousSyscallsBlockedByDefault(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules()

	// bpf syscall (nr 321 on x86_64) is blocked by the default seccomp filter.
	// Seccomp returns EPERM (errno 1). The python program completes normally,
	// demonstrating normal syscalls (read, write, exec) are unaffected.
	s.whenRun("python3", "-c",
		"import ctypes,ctypes.util;lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);lib.syscall(321,0,0,0);print('EPERM' if ctypes.get_errno()==1 else 'OTHER')")

	s.thenExitCode(0)
	s.thenStdoutContains("EPERM")
}

// TestE2E_RestrictingSyscalls_AllowSpecificSyscallViaConfigRule tests that a
// syscall:allow rule permits a specific blocked syscall through the seccomp filter
// while other dangerous syscalls remain blocked.
func TestE2E_RestrictingSyscalls_AllowSpecificSyscallViaConfigRule(t *testing.T) {
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules("syscall:allow:ptrace")

	// With syscall:allow:ptrace, PTRACE_TRACEME passes through seccomp.
	// SYS_PTRACE = 101 on x86_64. The kernel handles the call instead of
	// seccomp blocking it, so errno is not EPERM.
	s.whenRun("python3", "-c",
		"import ctypes,ctypes.util;lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);lib.syscall(101,0,0,0,0);print('EPERM' if ctypes.get_errno()==1 else 'ALLOWED')")

	s.thenExitCode(0)
	s.thenStdoutContains("ALLOWED")

	// bpf (nr 321) remains blocked by seccomp.
	s.whenRun("python3", "-c",
		"import ctypes,ctypes.util;lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);lib.syscall(321,0,0,0);print('EPERM' if ctypes.get_errno()==1 else 'OTHER')")

	s.thenExitCode(0)
	s.thenStdoutContains("EPERM")
}
