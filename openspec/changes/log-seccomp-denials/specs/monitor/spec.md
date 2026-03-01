## ADDED Requirements

### Requirement: Blocked syscall tracing

When seccomp filtering is active, the monitor SHALL include ruleable blocked syscall names in the strace trace expression and log attempted calls as `SYSCALL` entries. Defense-in-depth syscalls are blocked silently by the BPF filter without monitor tracing. When seccomp filtering is not active (e.g., `--no-sandbox` mode), blocked syscalls SHALL NOT be traced.

The monitor SHALL distinguish between denied and allowed blocked syscalls:
- Syscalls still in the active blocklist: logged as `SYSCALL / <name> / DENY / seccomp`
- Syscalls removed from the blocklist by `syscall:allow` rules: logged as `SYSCALL / <name> / OK / syscall:allow:<name>`

Blocked syscalls SHALL be intercepted before filesystem access processing. They SHALL NOT go through path resolution, operation type mapping, or filesystem rule checking.

#### Scenario: Blocked syscall logged as DENY when seccomp active

- **WHEN** seccomp filtering is active
- **AND** the sandboxed process calls a blocked syscall (e.g., bpf)
- **THEN** the monitor logs entry: Operation=`SYSCALL`, Target=`bpf`, Result=`DENY`, Rule=`seccomp`

#### Scenario: Allowed syscall logged as OK when seccomp active

- **WHEN** seccomp filtering is active
- **AND** config contains `syscall:allow:bpf`
- **AND** the sandboxed process calls bpf
- **THEN** the monitor logs entry: Operation=`SYSCALL`, Target=`bpf`, Result=`OK`, Rule=`syscall:allow:bpf`

#### Scenario: No SYSCALL entries when seccomp disabled

- **WHEN** seccomp filtering is not active (e.g., `--no-sandbox` mode)
- **AND** the sandboxed process calls a normally-blocked syscall
- **THEN** no `SYSCALL` `DENY` entry appears in the log (entries appear as `UNENFORCED` instead)

#### Scenario: File-group blocked syscall intercepted before ignore list

- **WHEN** seccomp filtering is active
- **AND** the sandboxed process calls `mount` (which is in both the blocked list and the monitor's ignored syscalls)
- **THEN** the monitor logs entry: Operation=`SYSCALL`, Target=`mount`, Result=`DENY`, Rule=`seccomp`
- **AND** the entry is NOT suppressed by the file-syscall ignore list

#### Scenario: Non-file blocked syscall parsed

- **WHEN** seccomp filtering is active
- **AND** the sandboxed process calls `ptrace` (not in the file trace group, no path argument)
- **THEN** the monitor logs entry: Operation=`SYSCALL`, Target=`ptrace`, Result=`DENY`, Rule=`seccomp`

#### Scenario: Blocked syscall during bwrap setup not logged

- **WHEN** seccomp filtering is active with bwrap
- **AND** bwrap calls mount/pivot_root/unshare during sandbox setup (before seccomp is applied)
- **THEN** these calls are skipped as part of the setup phase and do NOT produce SYSCALL entries
