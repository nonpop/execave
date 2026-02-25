## ADDED Use Cases

### Use Case: View seccomp-denied syscall attempts in access log

The user runs a command that attempts dangerous syscalls (e.g., ptrace, mount). When seccomp filtering is active, denied attempts appear as `SYSCALL` entries in the access log, giving visibility into what the sandboxed process tried to do.

- **GIVEN** a config with rule `fs:ro:/usr/lib`
- **AND** seccomp filtering is active (default, `--allow-all-syscalls` not set)
- **WHEN** the user runs `execave --monitor -- python3 -c "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)"`
- **THEN** the web UI displays an entry with operation `SYSCALL`, target `bpf`, result `DENY`, rule `seccomp`

### Use Case: Verify seccomp filter is active by presence of SYSCALL entries

The user verifies the seccomp filter is working by observing that blocked syscall attempts produce `SYSCALL` entries. When the filter is disabled via `--allow-all-syscalls`, the same attempts produce no `SYSCALL` entries.

- **GIVEN** a config with rule `fs:ro:/usr/lib`
- **WHEN** the user runs `execave --monitor -- python3 -c "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)"` with seccomp active
- **THEN** the web UI displays a `SYSCALL bpf DENY seccomp` entry
- **AND** when the user restarts with "Allow all syscalls" checked
- **AND** runs the same command
- **THEN** no `SYSCALL` entry appears in the web UI

### Use Case: Seccomp-denied syscall entries deduplicated

The user runs a command that repeatedly attempts the same blocked syscall. Each unique syscall name appears only once in the access log.

- **GIVEN** a config with rule `fs:ro:/usr/lib`
- **AND** seccomp filtering is active
- **WHEN** the user runs `execave --monitor -- sh -c "python3 -c 'import ctypes; l=ctypes.CDLL(None); l.syscall(321,0,0,0); l.syscall(321,0,0,0)'"`
- **THEN** the web UI displays exactly one `SYSCALL bpf DENY seccomp` entry

### Use Case: Suppress expected syscall denials with syscall:nolog

The user adds a `syscall:nolog` rule to hide known harmless denied syscalls from the access log display.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `syscall:nolog:bpf`
- **AND** seccomp filtering is active
- **WHEN** the user runs `execave --monitor -- python3 -c "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)"`
- **THEN** the web UI does not display the `SYSCALL bpf DENY` entry by default
- **AND** unchecking "Apply nolog rules" reveals the entry

### Use Case: Allowed syscall logged as OK

When a syscall is allowed via `syscall:allow`, it is permitted by the seccomp filter and appears as `SYSCALL / OK` in the access log. Like other OK entries, it is hidden by default and visible when "Denied only" is unchecked.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `syscall:allow:bpf`
- **AND** seccomp filtering is active
- **WHEN** the user runs `execave --monitor -- python3 -c "import ctypes; ctypes.CDLL(None).syscall(321, 0, 0, 0)"`
- **THEN** by default, no `SYSCALL bpf` entry appears in the web UI (OK entries are hidden)
- **AND** when the user unchecks "Denied only"
- **THEN** the web UI displays an entry with operation `SYSCALL`, target `bpf`, result `OK`, rule `syscall:allow:bpf`
