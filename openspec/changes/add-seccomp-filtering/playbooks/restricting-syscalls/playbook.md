## ADDED Use Cases

### Use Case: Dangerous syscalls blocked by default

The user runs a command in the sandbox. Dangerous syscalls (ptrace, bpf, io_uring, kexec_load, etc.) are blocked by seccomp and return EPERM, without the user needing any extra configuration.

- **GIVEN** a config with rule `fs:ro:/usr`
- **WHEN** the user runs `execave -- <program-that-calls-blocked-syscall>`
- **THEN** the blocked syscall returns EPERM
- **AND** normal syscalls (read, write, open, etc.) work as expected

### Use Case: Allow specific syscall via config rule

The user needs to run a program that requires a normally-blocked syscall (e.g., a debugger using ptrace). They add a `syscall:allow:<name>` rule to the config to selectively permit that syscall through the seccomp filter.

- **GIVEN** a config with rules `fs:ro:/usr` and `syscall:allow:ptrace`
- **WHEN** the user runs `execave -- <program-that-calls-ptrace>`
- **THEN** ptrace is not blocked by seccomp (may still fail due to namespace restrictions)
- **AND** all other dangerous syscalls remain blocked

