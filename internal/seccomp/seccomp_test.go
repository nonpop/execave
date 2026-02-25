package seccomp

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// expectedInstructionCount returns the expected number of BPF instructions in Filter.
// Formula: 3 (preamble) + len(blockedSyscalls) + 3 (ALLOW/DENY/KILL).
func expectedInstructionCount() int {
	return len(blockedSyscalls) + 6
}

func TestFilter_ByteLengthMatchesExpectedInstructionCount(t *testing.T) {
	data := Filter()
	expectedBytes := expectedInstructionCount() * 8 // each SockFilter is 8 bytes
	assert.Len(t, data, expectedBytes)
}

func TestFilter_ArchCheckIsFirstInstruction(t *testing.T) {
	data := Filter()
	require.GreaterOrEqual(t, len(data), 8)

	var insn unix.SockFilter
	require.NoError(t, binary.Read(bytes.NewReader(data[:8]), binary.NativeEndian, &insn))

	// First instruction must be BPF_LD | BPF_W | BPF_ABS loading from offset 4 (arch)
	assert.Equal(t, bpfLdWAbs, insn.Code)
	assert.Equal(t, seccompDataOffsetArch, insn.K)
}

func TestFilter_EachBlockedSyscallPresentInFilter(t *testing.T) {
	data := Filter()
	require.GreaterOrEqual(t, len(data), 8)

	// Parse all instructions
	r := bytes.NewReader(data)
	jeqK := make(map[uint32]bool)
	for r.Len() >= 8 {
		var insn unix.SockFilter
		require.NoError(t, binary.Read(r, binary.NativeEndian, &insn))
		if insn.Code == bpfJmpJeqK {
			jeqK[insn.K] = true
		}
	}

	// Every blocked syscall must appear as a JEQ K value
	for _, sc := range blockedSyscalls {
		assert.True(t, jeqK[sc.nr])
	}
}

func TestBlockedSyscallNames_ReturnsExpectedNames(t *testing.T) {
	names := BlockedSyscallNames()
	assert.NotEmpty(t, names)
	assert.Len(t, names, len(blockedSyscalls))
	assert.Equal(t, "ptrace", names[0])
	assert.Contains(t, names, "syslog")
	assert.Contains(t, names, "mount")
}

func TestRuleableSyscallNames_ExcludesDefenseOnlySyscalls(t *testing.T) {
	names := RuleableSyscallNames()

	// Known ruleable syscalls must be present.
	assert.Contains(t, names, "ptrace")
	assert.Contains(t, names, "bpf")
	assert.Contains(t, names, "mount")
	assert.Contains(t, names, "reboot")

	// Defense-in-depth syscalls must be absent.
	defenseOnly := []string{
		"kexec_load", "kexec_file_load",
		"init_module", "finit_module", "delete_module",
		"settimeofday", "adjtimex", "clock_adjtime",
		"syslog", "acct",
		"swapon", "swapoff",
		"nfsservctl",
	}
	for _, name := range defenseOnly {
		assert.NotContains(t, names, name)
	}
}

func TestRuleableSyscallNames_IsSubsetOfBlockedSyscallNames(t *testing.T) {
	blocked := make(map[string]bool)
	for _, name := range BlockedSyscallNames() {
		blocked[name] = true
	}
	for _, name := range RuleableSyscallNames() {
		assert.True(t, blocked[name])
	}
}

func TestFilterPipeWithAllowed_ExcludesAllowedSyscalls(t *testing.T) {
	// Full filter
	fullPipe, err := FilterPipe(nil)
	require.NoError(t, err)
	fullData, err := io.ReadAll(fullPipe)
	require.NoError(t, err)
	_ = fullPipe.Close()

	// Filter with one syscall allowed
	allowed := map[string]bool{"bpf": true}
	reducedPipe, err := FilterPipe(allowed)
	require.NoError(t, err)
	reducedData, err := io.ReadAll(reducedPipe)
	require.NoError(t, err)
	_ = reducedPipe.Close()

	// Reduced filter should be shorter by exactly 1 JEQ instruction (8 bytes)
	assert.Len(t, reducedData, len(fullData)-8)
}

func TestFilterPipe_ReturnsReadableFileWithCorrectContent(t *testing.T) {
	pipe, err := FilterPipe(nil)
	require.NoError(t, err)
	defer pipe.Close() //nolint:errcheck // best-effort close in test

	got, err := io.ReadAll(pipe)
	require.NoError(t, err)
	assert.Equal(t, Filter(), got)
}
