## Context

Execave isolates processes via Linux namespaces and bind mounts (bubblewrap) but does not restrict syscalls. The kernel attack surface — ptrace, bpf, io_uring, kexec, namespace manipulation — remains fully available inside the sandbox. This is a gap in defense-in-depth: a kernel vulnerability exploitable via these syscalls could escape the namespace isolation.

Two execution paths exist:
- **Direct**: `sandbox.Run()` → `exec.CommandContext("bwrap", args...)` — no ExtraFiles
- **Monitored**: `monitor.Run()` → `exec.CommandContext("strace", args...)` — ExtraFiles[0] = strace pipe (fd 3)

The seccomp filter must work in both paths.

## Goals / Non-Goals

**Goals:**
- Block ~32 dangerous syscalls by default via seccomp-bpf deny-list
- Provide `--allow-all-syscalls` CLI flag to disable filtering
- Graceful failure (EPERM, not SIGKILL) for blocked syscalls
- Support both amd64 and arm64

**Non-Goals:**
- Argument-level filtering (e.g., blocking `clone` with specific flags) — too complex for a deny-list
- Configurable per-syscall allowlisting — single profile only
- Config-file-based seccomp control — CLI/UI only to prevent config tampering from disabling the filter

## Decisions

### 1. BPF deny-list via bwrap `--seccomp <fd>`

**Decision**: Build a classic BPF program that blocks specific syscalls, pass to bwrap via `--seccomp <fd>` using a pipe.

**Why**: bwrap already supports seccomp filters via fd. No need for a separate seccomp library or privileged setup. The filter runs inside bwrap's sandbox setup — applied before the user command starts.

**Alternatives considered**:
- `libseccomp-golang`: Requires CGo + C library dependency. Overkill for a static deny-list.
- Allow-list approach: Would break too many programs. A deny-list of dangerous syscalls is the right granularity for dev tool sandboxing.

### 2. Use `golang.org/x/sys/unix` for BPF construction

**Decision**: Build raw `unix.SockFilter` structs directly. Use `SYS_*` and `AUDIT_ARCH_*` constants from `golang.org/x/sys/unix`. Serialize with `encoding/binary.NativeEndian`.

**Why**: `x/sys/unix` is already an indirect dependency. The BPF program is small (~40 instructions) and straightforward. No need for `x/net/bpf` or other abstractions.

### 3. Pipe-based fd passing with architecture-aware fd numbering

**Decision**: Create `os.Pipe()`, write compiled filter, close write end, pass read end via `cmd.ExtraFiles`.

- **Direct path** (`sandbox.Run`): seccomp pipe is ExtraFiles[0] → fd 3. Add `--seccomp 3` to bwrap args.
- **Monitored path** (`monitor.Run`): strace pipe is ExtraFiles[0] → fd 3. Seccomp pipe is ExtraFiles[1] → fd 4. Add `--seccomp 4` to bwrap args.

The fd passes through strace to bwrap because strace fork/exec's its child, and Go's `exec.Cmd.ExtraFiles` clears close-on-exec on passed fds. Strace doesn't close fds it doesn't own.

**Why**: Pipe is simple, fits in buffer (~320 bytes for 40 instructions), no temp files or cleanup needed.

### 4. EPERM for blocked syscalls, KILL for wrong architecture

**Decision**: Blocked syscalls return `SECCOMP_RET_ERRNO | EPERM`. Wrong architecture (e.g., x32 ABI on x86_64) returns `SECCOMP_RET_KILL_PROCESS`.

**Why**: EPERM is graceful — programs get a clear error and can handle it. KILL for wrong arch prevents syscall table confusion (x32 syscall numbers differ from x86_64).

### 5. CLI-only toggle, not in config file

**Decision**: `--allow-all-syscalls` is a CLI flag only. Not configurable in TOML.

**Why**: If it were in config, a process that can modify the config file (despite protection) could disable seccomp for subsequent runs. CLI-only means the user explicitly chooses to relax security at invocation time.

### 6. BPF program structure

```
LD [4]                        # Load seccomp_data.arch
JEQ <AUDIT_ARCH>, +1, kill    # Check architecture
LD [0]                        # Load seccomp_data.nr
JEQ SYS_PTRACE, deny          # Check each blocked syscall
JEQ SYS_BPF, deny
...
RET SECCOMP_RET_ALLOW          # Default: allow
deny: RET SECCOMP_RET_ERRNO|EPERM
kill: RET SECCOMP_RET_KILL_PROCESS
```

Architecture constant selected at runtime based on `runtime.GOARCH`. Syscall numbers come from `unix.SYS_*` which are arch-specific at compile time.

## Risks / Trade-offs

- **[Blocked debuggers]** → gdb/strace inside sandbox won't work (ptrace blocked). Mitigation: `--allow-all-syscalls` flag. Document in playbook.
- **[io_uring blocking]** → Some modern programs use io_uring for async I/O. Mitigation: These are rare in dev tool contexts; `--allow-all-syscalls` available.
- **[New mount API]** → Blocking `fsopen`/`fsmount`/etc. may affect container tools inside sandbox. Mitigation: Container-in-container is already impractical without unshare; `--allow-all-syscalls` available.
- **[Seccomp filter bypass via fd leak]** → If bwrap fails to read the filter, it may start without seccomp. Mitigation: bwrap treats `--seccomp` as mandatory — if the fd read fails, bwrap exits with error.
- **[x32 ABI]** → x32 syscall numbers differ. Mitigation: Wrong architecture → KILL_PROCESS.
