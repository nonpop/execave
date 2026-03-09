package monitor

import (
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/syscallrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseSyscallRule(t *testing.T, ruleBody string) syscallrules.Rule {
	t.Helper()
	rule, err := syscallrules.ParseRule(ruleBody, "")
	require.NoError(t, err)
	return rule
}

func TestMapSyscallToOperation(t *testing.T) {
	tests := []struct {
		name     string
		syscall  string
		line     string
		expected operationType
	}{
		{"open read", "open", `open("/file", O_RDONLY)`, operationRead},
		{"open write", "open", `open("/file", O_WRONLY)`, operationWrite},
		{"open rdwr", "open", `open("/file", O_RDWR)`, operationWrite},
		{"open create", "open", `open("/file", O_CREAT)`, operationWrite},
		// Filenames containing flag names should not cause misclassification
		{"open read file named O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/O_CREAT", O_RDONLY) = 3`, operationRead},
		{"open read file named O_WRONLY", "openat", `12345 openat(AT_FDCWD, "/tmp/O_WRONLY", O_RDONLY) = 3`, operationRead},
		{"open read file named O_RDWR", "openat", `12345 openat(AT_FDCWD, "/tmp/O_RDWR", O_RDONLY) = 3`, operationRead},
		{"open read path with O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/test_O_CREAT.txt", O_RDONLY) = 3`, operationRead},
		{"open write file named O_CREAT", "openat", `12345 openat(AT_FDCWD, "/tmp/O_CREAT", O_CREAT|O_WRONLY, 0644) = 3`, operationWrite},
		{"stat", "stat", `stat("/file")`, operationRead},
		{"fstatat", "fstatat", `fstatat(AT_FDCWD, "/file", ...)`, operationRead},
		{"newfstatat", "newfstatat", `newfstatat(AT_FDCWD, "/file", ...)`, operationRead},
		{"read", "read", `read(3, ...)`, operationRead},
		{"write", "write", `write(3, ...)`, operationWrite},
		{"unlink", "unlink", `unlink("/file")`, operationWrite},
		{"mkdir", "mkdir", `mkdir("/dir")`, operationWrite},
		{"chmod", "chmod", `chmod("/file", 0755)`, operationWrite},
		{"execve", "execve", `execve("/bin/sh")`, operationRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapSyscallToOperation(tt.syscall, tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildStraceArgs(t *testing.T) {
	args := buildStraceArgs([]string{"echo", "hello"}, 3, nil)

	assert.Contains(t, args, "-f")
	assert.Contains(t, args, "-y")
	assert.Contains(t, args, "trace=file,fchdir")
	assert.Contains(t, args, "-qq")
	assert.Contains(t, args, "/proc/self/fd/3")
	assert.Contains(t, args, "echo")
	assert.Contains(t, args, "hello")
}

func TestBuildStraceArgs_WithBlockedSyscalls(t *testing.T) {
	sr := syscallrules.NewResolver(
		[]syscallrules.Rule{mustParseSyscallRule(t, "allow:bpf")},
		seccomp.RuleableSyscallNames(),
	)
	args := buildStraceArgs([]string{"echo", "hello"}, 3, sr)

	var traceArg string
	for _, a := range args {
		if strings.HasPrefix(a, "trace=") {
			traceArg = a
			break
		}
	}
	require.NotEmpty(t, traceArg)

	assert.Contains(t, traceArg, "file,fchdir")
	assert.Contains(t, traceArg, ",mount,")
	assert.Contains(t, traceArg, ",ptrace")
	assert.Contains(t, traceArg, ",bpf,")

	// bpf < mount < ptrace alphabetically
	assert.Less(t, strings.Index(traceArg, ",bpf,"), strings.Index(traceArg, ",mount,"))
	assert.Less(t, strings.Index(traceArg, ",mount,"), strings.Index(traceArg, ",ptrace"))
}

func TestBuildStraceArgs_WithoutBlockedSyscalls(t *testing.T) {
	args := buildStraceArgs([]string{"echo", "hello"}, 3, nil)

	var traceArg string
	for _, a := range args {
		if strings.HasPrefix(a, "trace=") {
			traceArg = a
			break
		}
	}
	assert.Equal(t, "trace=file,fchdir", traceArg)
}

func TestBuildStraceArgs_CommandPassthrough(t *testing.T) {
	command := []string{"/usr/bin/bwrap", "--seccomp", "4", "--unshare-all", "--", "true"}
	args := buildStraceArgs(command, 3, nil)

	found := false
	for i, a := range args {
		if a == "--seccomp" && i+1 < len(args) && args[i+1] == "4" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestBuildStraceArgs_NoSeccompWhenAbsent(t *testing.T) {
	command := []string{"/usr/bin/bwrap", "--unshare-all", "--", "true"}
	args := buildStraceArgs(command, 3, nil)

	for i, a := range args {
		if a == "--seccomp" {
			t.Errorf("unexpected --seccomp at index %d", i)
		}
	}
}
