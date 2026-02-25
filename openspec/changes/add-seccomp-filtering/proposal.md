## Why

Execave sandboxes processes using namespaces and bind mounts but does not filter syscalls. Dangerous syscalls like `ptrace`, `bpf`, `io_uring`, and `kexec_load` remain available inside the sandbox, enabling exploit primitives, namespace escape attempts, and kernel attack surface. Adding a seccomp-bpf deny-list provides defense-in-depth by blocking these syscalls by default.

## What Changes

- New `internal/seccomp/` package that builds a classic BPF deny-list filter targeting ~32 dangerous syscalls (kernel modules, BPF, ptrace, io_uring, namespace manipulation, mount, keyring, time manipulation, etc.)
- Sandbox passes the compiled filter to bwrap via `--seccomp <fd>` using a pipe
- Seccomp filtering is enabled by default; `--allow-all-syscalls` CLI flag disables it
- Web UI gets an "Allow all syscalls" checkbox (default off) to toggle per-run
- Blocked syscalls return EPERM (graceful failure); wrong architecture kills the process
- **Security impact**: This change adds a new enforcement layer inside the sandbox boundary. It restricts the kernel attack surface available to sandboxed processes. The `--allow-all-syscalls` flag relaxes this — it is CLI-only (not configurable in TOML) to prevent config tampering from disabling the filter.

## Playbooks

### New Playbooks
- `restricting-syscalls`: Running sandboxed commands with dangerous syscalls blocked; using `--allow-all-syscalls` when programs need them (e.g., debuggers)

### Modified Playbooks
- `preventing-sandbox-escape`: Seccomp adds a new defense layer to the existing escape prevention story

## Capabilities

### New Capabilities
- `seccomp`: Seccomp-bpf filter generation, blocked syscall list, filter-to-fd plumbing

### Modified Capabilities
- `sandbox`: Sandbox gains seccomp fd plumbing and `--seccomp` arg insertion into bwrap invocation
- `runner`: Runner gains mutable `allowAllSyscalls` state, creates seccomp pipe per run
- `web-ui`: Web UI gains "Allow all syscalls" checkbox and passes state to runner on start
- `monitor`: Monitor gains seccomp file fd plumbing (fd 4, after strace pipe at fd 3)

## Impact

- **Code**: New `internal/seccomp/` package. Modified: `internal/sandbox/`, `internal/monitor/`, `internal/runner/`, `internal/webui/`, `cmd/execave/`
- **Dependencies**: Uses `golang.org/x/sys/unix` (already indirect dependency) for `SYS_*`, `AUDIT_ARCH_*`, `SockFilter` constants
- **CLI**: New `--allow-all-syscalls` flag
- **Security boundary**: Adds kernel-enforced syscall restriction inside sandbox. Trust boundary unchanged — seccomp filter is built by trusted execave process
