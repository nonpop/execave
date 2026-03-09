package e2e_test

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func Test_RestrictingSyscalls_DangerousSyscallsBlockedByDefault(t *testing.T) {
	// Dangerous syscalls are blocked by the default seccomp filter and return EPERM.
	// Normal syscalls pass through unaffected, verifying the filter does not over-block.
	requireAMD64(t)

	for _, tt := range []struct {
		name    string
		nr      int
		args    string
		wantOut string
	}{
		// Ruleable blocked syscall — blocked by default, can be allowed via config.
		{"bpf", unix.SYS_BPF, ",0,0,0", "EPERM"},
		// Defense-in-depth blocked syscall — always blocked, cannot be allowed via config.
		{"kexec_load", unix.SYS_KEXEC_LOAD, ",0,0,0,0,0,0", "EPERM"},
		// Normal syscall — must not be blocked.
		{"getpid", unix.SYS_GETPID, "", "OK"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenPython3()
			s.givenRules()
			s.whenRun("python3", "-c",
				fmt.Sprintf(
					"import ctypes,ctypes.util;"+
						"lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);"+
						"ctypes.set_errno(0);"+
						"lib.syscall(%d%s);"+
						"e=ctypes.get_errno();"+
						"print('EPERM' if e==1 else 'OK')",
					tt.nr, tt.args))
			s.thenExitCode(0)
			s.thenStdoutContains(tt.wantOut)
		})
	}
}

func Test_RestrictingSyscalls_AllowSpecificSyscallViaConfigRule(t *testing.T) {
	// A syscall:allow rule permits the named syscall through seccomp while other
	// blocked syscalls remain blocked. Multiple allow rules each take effect.
	requireAMD64(t)

	for _, tt := range []struct {
		name    string
		rules   []string
		nr      int
		args    string
		wantOut string
	}{
		{
			// The allowed syscall passes through seccomp to the kernel.
			name:    "allowed_syscall_passes_through",
			rules:   []string{"syscall:allow:ptrace"},
			nr:      unix.SYS_PTRACE,
			args:    ",0,0,0,0",
			wantOut: "ALLOWED",
		},
		{
			// The allow is selective: other blocked syscalls remain blocked.
			name:    "other_blocked_syscalls_remain_blocked",
			rules:   []string{"syscall:allow:ptrace"},
			nr:      unix.SYS_BPF,
			args:    ",0,0,0",
			wantOut: "EPERM",
		},
		{
			// Multiple allow rules: each named syscall is individually allowed.
			name:    "multiple_allow_rules",
			rules:   []string{"syscall:allow:ptrace", "syscall:allow:bpf"},
			nr:      unix.SYS_BPF,
			args:    ",0,0,0",
			wantOut: "ALLOWED",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenPython3()
			s.givenRules(tt.rules...)
			s.whenRun("python3", "-c",
				fmt.Sprintf(
					"import ctypes,ctypes.util;"+
						"lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);"+
						"ctypes.set_errno(0);"+
						"lib.syscall(%d%s);"+
						"e=ctypes.get_errno();"+
						"print('EPERM' if e==1 else 'ALLOWED')",
					tt.nr, tt.args))
			s.thenExitCode(0)
			s.thenStdoutContains(tt.wantOut)
		})
	}
}
