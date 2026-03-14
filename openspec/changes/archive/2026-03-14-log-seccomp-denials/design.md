## Context

The seccomp BPF filter blocks ~34 dangerous syscalls with SECCOMP_RET_ERRNO (EPERM). The monitor traces only filesystem syscalls (`strace -e trace=file,fchdir`), so blocked syscall attempts are invisible. The `--allow-all-syscalls` flag is all-or-nothing.

Current data flow: strace output → parser (regex-based) → `processAccessEntry` (path resolution + rule checking) → `accesslog.Logger` → text log.

The parser expects file-oriented syscall formats (`syscall("path"...)`) and panics on unknown syscall names. Blocked syscalls like `ptrace(PTRACE_TRACEME)` have no path argument and aren't in the strace trace expression.

## Goals / Non-Goals

**Goals:**
- Blocked syscall attempts visible as SYSCALL entries in the access log
- Configurable per-syscall allow rules (`syscall:allow:<name>`)
- Display filtering via `syscall:nolog:<name>`
- Allowed syscalls logged as SYSCALL/OK (hidden by default, visible with "show all")

**Non-Goals:**
- Replacing strace-based monitoring with eBPF (future work)
- Fixing ptrace nesting (monitor strace + user strace — fundamental Linux limitation)
- Syscall argument logging (only name and result)

## Decisions

### 1. Seccomp package: struct slice for blocked syscalls

Refactor `blockedSyscalls` from `[]uint32` to `[]blockedSyscall{name string, nr uint32}`. This keeps names and numbers co-located, preserves slice ordering (deterministic BPF output), and avoids a separate name→number map that could drift.

Export `BlockedSyscallNames() []string` for the monitor and config validator. `Filter()` extracts numbers internally.

*Alternative: `map[string]uint32`.* Rejected because map iteration is non-deterministic, producing different BPF bytecode across builds.

### 2. Seccomp filter accepts allowed set

Add `FilterPipeWithAllowed(allowed map[string]bool) (*os.File, error)` that excludes allowed names from the blocklist before building the BPF program. The existing `FilterPipe()` becomes shorthand for `FilterPipeWithAllowed(nil)`.

The allowed set is validated at config parse time — only names in `BlockedSyscallNames()` are accepted. The filter function trusts its input (internal API).

**Threat analysis:** A wrong name in the allowed set means a dangerous syscall stays blocked (fail-safe). A valid name means the user explicitly chose to allow it — same trust model as `--allow-all-syscalls` but scoped.

### 3. Config: `syscall:allow` and `syscall:nolog` rules

Parsed alongside `fs:` and `net:` rules in `config.ParseRules`. The config struct gets two new fields: `SyscallAllowRules []string` and `SyscallNologRules []string` (just syscall names, no paths or complex matching).

Validation:
- Name must be in `seccomp.BlockedSyscallNames()` — rejects typos and non-blocked names
- Duplicate names within allow or within nolog rejected (consistent with fs/net duplicate rules)
- `syscall:allow:X` + `syscall:nolog:X` is valid (different rule namespaces)

### 4. Monitor: conditional trace extension

When `seccompFile != nil`, the monitor:
1. Stores `blockedSyscalls map[string]bool` (from `seccomp.BlockedSyscallNames()` minus allowed)
2. Extends `-e trace=file,fchdir,<blocked names>` in `buildStraceArgs`
3. Passes the blocked set to the parser

When `seccompFile == nil` (allow-all-syscalls), no extra tracing — SYSCALL entries don't appear.

The monitor also receives `allowedSyscalls map[string]bool` to know which syscalls to log as OK vs DENY.

### 5. Parser: fallback regex for non-file syscalls

Non-file blocked syscalls (`ptrace(PTRACE_TRACEME)`, `bpf(...)`, `reboot(...)`) don't have a quoted path argument. Existing regexes won't match them.

Add a generic fallback regex `^\d*\s*(\w+)\(` tried LAST in `parseLine`. If the name is in the blocked set, return a `parseResult` with the syscall name and empty path. The `parseLine` method receives the blocked set at parser construction.

File-group blocked syscalls (mount, chroot, etc.) already match existing regexes and parse normally — they're intercepted at the `processStraceLine` level.

### 6. processStraceLine: intercept before processAccessEntry

After the exit check, before `resolveCWD`/`processAccessEntry`: check `m.blockedSyscalls[result.syscall]`. If matched, log directly as:
- Denied: `{SYSCALL, syscallName, DENY, "seccomp"}`
- Allowed: `{SYSCALL, syscallName, OK, "syscall:allow:<name>"}`

This intercepts both file-group and non-file blocked syscalls before they reach `processAccessEntry` (where they'd hit `ignoredSyscalls` or trigger the unknown-syscall panic).

### 7. Nolog filtering for SYSCALL entries

The `logfilter.IsNolog` function needs to handle SYSCALL entries. For SYSCALL entries, match the target (syscall name) against `syscall:nolog` rules. This is a simple set lookup, unlike fs/net nolog which use path/domain matching.

The `accesslog.Entry` already carries a `Rule` field. The nolog check uses the config's `SyscallNologRules` set.

### 8. Access log: new constants

- `OperationSyscall OperationType = "SYSCALL"`
- `RuleSeccomp = "seccomp"` (used for denied entries)

No changes to deduplication or managed-path filtering — SYSCALL targets are syscall names, not paths, so managed-path filtering doesn't apply.

## Risks / Trade-offs

**[Strace version compatibility]** Some blocked syscall names (open_tree, move_mount, fsopen, etc.) are newer Linux 5.2+ syscalls. Old strace versions may not recognize them in `-e trace=`. → Mitigation: strace silently ignores unknown names in trace expressions. If a name is unrecognized, it simply won't be traced — benign failure.

**[Trace overhead]** Adding ~34 syscalls to the trace expression increases the set strace monitors. → Mitigation: these syscalls are rarely called by normal programs. The overhead is in strace's BPF filter setup (one-time), not per-syscall.

**[Cannot distinguish seccomp EPERM from capability EPERM]** When seccomp is active, blocked syscalls return EPERM from seccomp before reaching kernel permission checks. We log all attempts as DENY/seccomp. If somehow a blocked syscall reached the kernel (shouldn't happen), the result would still be EPERM. → Acceptable: the entry is accurate either way.

**[Allowed syscall OK logging requires tracing]** To log allowed syscalls as OK, they must remain in the strace trace expression even though seccomp won't block them. The kernel will process them normally and strace will see the return value. We log them as OK regardless of kernel return value (the seccomp filter allowed them). → Acceptable: the log shows what seccomp decided, not the kernel outcome.
