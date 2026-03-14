## ADDED Use Cases

### Use Case: Selectively allow a blocked syscall

The user needs a specific blocked syscall for their workload. They add a `syscall:allow` rule to permit it while keeping all other dangerous syscalls blocked.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `syscall:allow:bpf`
- **WHEN** the user runs `execave -- python3 -c "import ctypes; print(ctypes.CDLL(None).syscall(321, 0, 0, 0))"`
- **THEN** the bpf syscall is permitted by the seccomp filter (returns a kernel error, not EPERM from seccomp)
- **AND** all other dangerous syscalls remain blocked

### Use Case: Invalid syscall name rejected at config parse

The user misspells a syscall name or uses a name that is not in the blocked list. The config is rejected with a clear error message.

- **GIVEN** a config with rule `syscall:allow:ptraec`
- **WHEN** the user runs `execave --config execave.toml -- ls`
- **THEN** execave exits with an error indicating `ptraec` is not a valid ruleable syscall name

### Use Case: Defense-in-depth syscall rejected at config parse

The user tries to allow a syscall that the kernel already blocks inside the sandbox. The config is rejected because allowing it would have no effect.

- **GIVEN** a config with rule `syscall:allow:syslog`
- **WHEN** the user runs `execave --config execave.toml -- ls`
- **THEN** execave exits with an error indicating `syslog` is not a ruleable syscall name

### Use Case: Multiple syscall rules

The user allows multiple specific syscalls while keeping the rest blocked.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `syscall:allow:bpf`, and `syscall:allow:reboot`
- **WHEN** the user runs `execave -- python3 -c "import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(169,0xfee1dead,0x28121969,0x01234567)"`
- **THEN** both bpf and reboot are permitted by the seccomp filter
- **AND** all other dangerous syscalls remain blocked

### Use Case: Duplicate syscall allow rules rejected

The user accidentally adds the same `syscall:allow` rule twice. The config is rejected.

- **GIVEN** a config with rules `syscall:allow:ptrace` and `syscall:allow:ptrace`
- **WHEN** the user runs `execave --config execave.toml -- ls`
- **THEN** execave exits with an error indicating a duplicate syscall rule

### Use Case: Duplicate syscall nolog rules rejected

The user accidentally adds the same `syscall:nolog` rule twice. The config is rejected.

- **GIVEN** a config with rules `syscall:nolog:ptrace` and `syscall:nolog:ptrace`
- **WHEN** the user runs `execave --config execave.toml -- ls`
- **THEN** execave exits with an error indicating a duplicate syscall rule
