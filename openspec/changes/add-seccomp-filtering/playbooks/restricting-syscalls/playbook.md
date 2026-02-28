## ADDED Use Cases

### Use Case: Dangerous syscalls blocked by default

The user runs a command in the sandbox. Dangerous syscalls (ptrace, bpf, io_uring, kexec_load, etc.) are blocked by seccomp and return EPERM, without the user needing any extra configuration.

- **GIVEN** a config with rule `fs:ro:/usr`
- **WHEN** the user runs `execave -- <program-that-calls-blocked-syscall>`
- **THEN** the blocked syscall returns EPERM
- **AND** normal syscalls (read, write, open, etc.) work as expected

### Use Case: Allow all syscalls with CLI flag

The user needs to run a program that requires a normally-blocked syscall (e.g., a debugger using ptrace). They use the `--allow-all-syscalls` flag to disable seccomp filtering.

- **GIVEN** a config with rule `fs:ro:/usr`
- **WHEN** the user runs `execave --allow-all-syscalls -- <program-that-calls-blocked-syscall>`
- **THEN** the blocked syscall is not blocked by seccomp (may still fail due to namespace restrictions)

