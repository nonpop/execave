package seccomp_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"testing"

	"github.com/nonpop/execave/internal/seccomp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// BPF constants for inspecting the compiled filter.
const (
	bpfJmpJeqK uint16 = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRetK    uint16 = 0x06 // BPF_RET | BPF_K
)

// --- Requirement: Deny-list filter generation ---

func TestIntegration_DenyListFilterGeneration_FilterBlocksDangerousSyscall(t *testing.T) {
	data := filterBytes(t)
	insns := parseInstructions(t, data)

	// SYS_PTRACE must appear as a JEQ check that jumps to the DENY return.
	ptrace := uint32(unix.SYS_PTRACE)
	var found bool
	for _, insn := range insns {
		if insn.Code == bpfJmpJeqK && insn.K == ptrace {
			found = true
		}
	}
	assert.True(t, found)

	// The DENY instruction must use SECCOMP_RET_ERRNO|EPERM.
	denyFound := false
	for _, insn := range insns {
		if insn.Code == bpfRetK && insn.K == unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
			denyFound = true
		}
	}
	assert.True(t, denyFound)
}

func TestIntegration_DenyListFilterGeneration_FilterAllowsNormalSyscalls(t *testing.T) {
	data := filterBytes(t)
	insns := parseInstructions(t, data)

	// Normal syscalls (read, write, open, execve) must NOT appear as JEQ checks.
	normalSyscalls := map[uint32]string{
		unix.SYS_READ:   "read",
		unix.SYS_WRITE:  "write",
		unix.SYS_OPENAT: "openat",
		unix.SYS_EXECVE: "execve",
	}
	for _, insn := range insns {
		if insn.Code == bpfJmpJeqK {
			_, blocked := normalSyscalls[insn.K]
			assert.False(t, blocked)
		}
	}

	// The filter must end with a SECCOMP_RET_ALLOW instruction.
	allowFound := false
	for _, insn := range insns {
		if insn.Code == bpfRetK && insn.K == unix.SECCOMP_RET_ALLOW {
			allowFound = true
		}
	}
	assert.True(t, allowFound)
}

func TestIntegration_DenyListFilterGeneration_FilterKillsOnWrongArchitecture(t *testing.T) {
	data := filterBytes(t)
	insns := parseInstructions(t, data)

	// The filter must contain SECCOMP_RET_KILL_PROCESS for arch mismatch.
	killFound := false
	for _, insn := range insns {
		if insn.Code == bpfRetK && insn.K == unix.SECCOMP_RET_KILL_PROCESS {
			killFound = true
		}
	}
	assert.True(t, killFound)
}

// --- Requirement: Filter pipe creation ---

func TestIntegration_FilterPipeCreation_FilterPipeReturnsReadableFile(t *testing.T) {
	pipe, err := seccomp.FilterPipe(nil)
	require.NoError(t, err)
	defer pipe.Close() //nolint:errcheck // best-effort close in test

	got, err := io.ReadAll(pipe)
	require.NoError(t, err)

	// Filter must be non-empty and a valid BPF program (multiple of 8 bytes).
	assert.NotEmpty(t, got)
	assert.Zero(t, len(got)%8)
}

// --- Requirement: Architecture support ---

func TestIntegration_ArchitectureSupport_FilterUsesCorrectArchitecture(t *testing.T) {
	data := filterBytes(t)
	insns := parseInstructions(t, data)

	// The second instruction must be a JEQ checking the architecture constant.
	require.GreaterOrEqual(t, len(insns), 2)
	archCheck := insns[1]
	assert.Equal(t, bpfJmpJeqK, archCheck.Code)

	switch runtime.GOARCH {
	case "amd64":
		assert.Equal(t, uint32(unix.AUDIT_ARCH_X86_64), archCheck.K)
	case "arm64":
		assert.Equal(t, uint32(unix.AUDIT_ARCH_AARCH64), archCheck.K)
	default:
		t.Skipf("architecture %s not tested", runtime.GOARCH)
	}
}

// --- Requirement: Ruleable syscall names ---

func TestIntegration_RuleableSyscallNames_ExcludesDefenseOnlySyscalls(t *testing.T) {
	ruleable := seccomp.RuleableSyscallNames()
	assert.Contains(t, ruleable, "ptrace")
	assert.Contains(t, ruleable, "bpf")

	// Defense-in-depth syscalls must not be ruleable.
	assert.NotContains(t, ruleable, "kexec_load")
	assert.NotContains(t, ruleable, "init_module")
	assert.NotContains(t, ruleable, "syslog")
	assert.NotContains(t, ruleable, "nfsservctl")
}

func TestIntegration_FilterPipeWithAllowed_ExcludesAllowedSyscalls(t *testing.T) {
	fullPipe, err := seccomp.FilterPipe(nil)
	require.NoError(t, err)
	fullData, err := io.ReadAll(fullPipe)
	require.NoError(t, err)
	_ = fullPipe.Close()

	allowed := map[string]bool{"bpf": true}
	reducedPipe, err := seccomp.FilterPipe(allowed)
	require.NoError(t, err)
	reducedData, err := io.ReadAll(reducedPipe)
	require.NoError(t, err)
	_ = reducedPipe.Close()

	// Reduced filter should be shorter by exactly 1 JEQ instruction (8 bytes).
	assert.Len(t, reducedData, len(fullData)-8)
}

// filterBytes returns the full deny-list filter bytes via FilterPipe.
func filterBytes(t *testing.T) []byte {
	t.Helper()
	pipe, err := seccomp.FilterPipe(nil)
	require.NoError(t, err)
	defer pipe.Close() //nolint:errcheck // best-effort close in test
	data, err := io.ReadAll(pipe)
	require.NoError(t, err)
	return data
}

// parseInstructions decodes a BPF program byte slice into SockFilter instructions.
func parseInstructions(t *testing.T, data []byte) []unix.SockFilter {
	t.Helper()
	r := bytes.NewReader(data)
	var insns []unix.SockFilter
	for r.Len() >= 8 {
		var insn unix.SockFilter
		require.NoError(t, binary.Read(r, binary.NativeEndian, &insn))
		insns = append(insns, insn)
	}
	return insns
}
