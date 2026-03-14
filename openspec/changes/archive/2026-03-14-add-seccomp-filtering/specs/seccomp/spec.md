## ADDED Requirements

### Requirement: Deny-list filter generation

The seccomp package SHALL generate a compiled BPF deny-list filter that blocks dangerous syscalls. The filter SHALL be returned as raw bytes suitable for bwrap's `--seccomp <fd>` flag. The blocked syscall list SHALL include: `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`, `acct`, `bpf`, `ptrace`, `unshare`, `setns`, `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `add_key`, `request_key`, `keyctl`, `perf_event_open`, `userfaultfd`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `personality`.

#### Scenario: Filter blocks a dangerous syscall
- **WHEN** `Filter()` is called
- **THEN** the returned BPF bytecode, when loaded as a seccomp filter, causes `SYS_PTRACE` to return EPERM

#### Scenario: Filter allows normal syscalls
- **WHEN** `Filter()` is called
- **THEN** the returned BPF bytecode, when loaded as a seccomp filter, allows `SYS_READ`, `SYS_WRITE`, `SYS_OPEN`, `SYS_EXECVE` to proceed normally

#### Scenario: Filter kills on wrong architecture
- **WHEN** the seccomp filter is loaded
- **AND** a syscall is made from a different architecture (e.g., x32 ABI on x86_64)
- **THEN** the process is killed with `SECCOMP_RET_KILL_PROCESS`

### Requirement: Filter pipe creation

The seccomp package SHALL provide `FilterPipe()` which creates an `os.Pipe`, writes the compiled filter to the write end, closes the write end, and returns the read end. The caller MUST close the read end after the child process has been started.

#### Scenario: FilterPipe returns readable file
- **WHEN** `FilterPipe()` is called
- **THEN** it returns a non-nil `*os.File` and no error
- **AND** reading from the file yields the same bytes as `Filter()`

### Requirement: Architecture support

The filter SHALL select the correct `AUDIT_ARCH_*` constant and `SYS_*` syscall numbers based on `runtime.GOARCH`. On amd64, the filter SHALL use `AUDIT_ARCH_X86_64`. On arm64, the filter SHALL use `AUDIT_ARCH_AARCH64`. Only syscalls that exist on the target architecture SHALL be included.

#### Scenario: Filter uses correct architecture on amd64
- **WHEN** `Filter()` is called on amd64
- **THEN** the BPF bytecode checks for `AUDIT_ARCH_X86_64`

#### Scenario: Filter uses correct architecture on arm64
- **WHEN** `Filter()` is called on arm64
- **THEN** the BPF bytecode checks for `AUDIT_ARCH_AARCH64`
