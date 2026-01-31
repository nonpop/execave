## Context

New project—no existing codebase. Building a CLI tool that wraps arbitrary commands in a bubblewrap sandbox with filesystem access controls defined in a per-project JSON config.

Key constraints:
- Linux-only (bubblewrap requirement)
- Must handle symlink resolution (check target permissions, not link path)
- Monitoring is opt-in due to strace performance overhead

## Goals / Non-Goals

**Goals:**
- Granular filesystem access control via simple config file
- Default-deny sandbox (starts empty, explicit whitelisting required)
- Clear access logging with rule attribution when monitoring enabled
- Single static binary distribution

**Non-Goals:**
- Network access control
- Cross-platform support
- GUI or interactive configuration
- Config inheritance/composition

## Decisions

### Language: Go

**Rationale:** Static binary distribution, good syscall support, straightforward CLI tooling.

### Config format: Flat rule array with sigils

```json
{
  "rules": [
    "fs:ro:/usr/bin",
    "fs:rw:/home/user/project",
    "fs:ro:/home/user/project/.git",
    "fs:none:/home/user/project/.env"
  ]
}
```

**Rationale:** Single array is simple. Rule type (`rw`, `ro`, `none`) encodes the permission level. Format anticipates future resource types (`net:`, `env:`).

**Alternatives considered:**
- Separate `allow`/`deny` arrays: More visual grouping but redundant given self-describing rules
- TOML: More readable but JSON is more universal and easier to generate programmatically

### Rule semantics

| Rule | Meaning |
|------|---------|
| `fs:rw:/path` | Read-write access to `/path/**` |
| `fs:ro:/path` | Read-only access to `/path/**` |
| `fs:none:/path` | No access to `/path/**` (dirs get tmpfs + chmod 0000; files get /dev/null bind) |

**Permission hierarchy:** `none` > `ro` > `rw` (strictest to most permissive)

**Resolution:**
1. Duplicate paths rejected at config load (config error)
2. Find the most specific rule (longest matching path prefix)
3. No match → deny (default-deny)

### Symlink handling: Resolve to target

When accessing a symlink, check read permission, then resolve to target and check permissions on the target path.

**Rationale:** We're protecting *data*, not filenames. A symlink to `/etc/shadow` shouldn't bypass restrictions just because the link lives in an allowed directory.

### Denial behavior: EACCES

Denied access returns `EACCES` (permission denied), not `ENOENT` (not found).

**Rationale:** Debuggability over obscurity. Agents will be less confused by explicit permission errors than mysterious missing files.

### Log format: Compact human-readable

```
READ  /etc/passwd              OK    fs:ro:/etc/passwd
WRITE /project/.git/config     DENY  fs:ro:/project/.git
READ  /project/.env            DENY  fs:none:/project/.env
```

**Rationale:** Human-readable for debugging. Machine parsing can come later if needed. Operations logged as READ/WRITE only (internal ops like STAT, LIST, EXEC mapped to READ).

### Monitoring: Optional strace tracing

| Mode | Flag | Sandbox | Logging |
|------|------|---------|---------|
| Sandbox only | (default) | Yes | No |
| Sandbox + monitor | `--monitor` | Yes | Yes |

**Rationale:** Users may want to see what the sandboxed process tried to access for debugging or auditing. The `--monitor` flag enables strace tracing while maintaining full sandbox isolation.

**Implementation:** strace wraps bwrap (`strace -- bwrap [args] -- [cmd]`). strace's `-f` flag follows forks through namespace boundaries.

### Monitoring: Separate log file

`--monitor` writes to `./execave-access.log` by default, or path specified via `--monitor=/path/to/log`.

**Rationale:** Keeps access log separate from command stdout/stderr. Default filename is predictable and discoverable.

## Security Analysis

### Sandbox Boundary Guarantees

Execave relies on Linux kernel isolation primitives via bubblewrap:

| Layer | Mechanism | Guarantee | Reference |
|-------|-----------|-----------|-----------|
| Filesystem | Mount namespaces | Sandboxed process sees isolated filesystem view | `man 7 mount_namespaces`, bwrap `--unshare-all` |
| Process isolation | PID namespaces | Child cannot see parent processes | bwrap `--unshare-pid` |
| User isolation | User namespaces | Maps container root to unprivileged host user | bwrap `--unshare-user` |
| Capabilities | User namespace mapping | Capabilities inside namespace don't grant host privileges | bwrap `--unshare-user`, kernel capability(7) |

**Key invariant**: All filesystem access goes through bubblewrap's mount namespace. No bind mounts = no access (default-deny).

See `docs/security-model.md` for detailed threat model and trust boundaries.

### Threat Analysis: What If This Fails?

**Config path normalization:**
- *Risk*: Relative or non-canonical paths could resolve unexpectedly, leading to user confusion about what's actually allowed
- *Mitigation*: Resolve relative paths against config directory (not CWD). Document resolution rules clearly
- *Test*: Verify paths resolve as documented with various relative paths, symlinks, redundant separators

**Rule resolution has edge case:**
- *Risk*: Incorrect "most specific" logic could grant write access to read-only subtree
- *Mitigation*: Unit tests for key scenarios, fuzz tests verify invariants (longest prefix wins, permission hierarchy respected)
- *Test*: Scenarios covering all permission hierarchy combinations

**Bwrap args constructed incorrectly:**
- *Risk*: Missing `--unshare-all` or wrong bind mount order could weaken isolation
- *Mitigation*: Unit tests for arg builder. E2E tests verify sandbox actually blocks access
- *Test*: Attempt to access denied path and assert EACCES

**Symlink resolution bypasses rules:**
- *Risk*: Symlink in allowed directory pointing to sensitive file could leak data
- *Mitigation*: Sandbox filesystem only contains explicitly allowed paths. Symlinks to non-allowed targets become dangling links inside the sandbox
- *Test*: Create symlink to `/etc/shadow` in allowed directory, verify denial

**strace parsing has bugs:**
- *Risk*: Incorrect syscall parsing could misattribute access or miss denials
- *Mitigation*: Monitoring is audit-only (read-only view). Cannot weaken sandbox
- *Impact*: Low (logging bugs don't affect security, only visibility)

**Config file modified by sandboxed process:**
- *Risk*: Process could modify its own rules to gain more access
- *Mitigation*: Force config file to read-only even if parent directory is rw
- *Test*: E2E test attempting to write config from sandbox

### Auditability

The system is designed for security auditing:

1. **Explicit-only access**: Empty filesystem by default. Every accessible path must appear in config
2. **Flat rule array**: Single JSON array with no inheritance or composition (what you see is what you get)
3. **Deterministic resolution**: Longest-prefix match + strictness hierarchy is algorithmically verifiable
4. **Access logging**: `--monitor` flag provides complete audit trail with rule attribution
5. **Debuggability**: EACCES (not ENOENT) makes denials visible to user

An auditor can:
- Read `execave.json` to see all allowed paths
- Run with `--monitor` to verify actual access patterns
- Diff log against config to detect unexpected access attempts

### References

- **Security model**: See `docs/security-model.md` for threat model, trust boundaries, and security invariants
- **Bubblewrap**: https://github.com/containers/bubblewrap - container sandboxing tool
- **Linux namespaces**: `man 7 namespaces`, `man 7 mount_namespaces`, `man 7 user_namespaces`
- **Capabilities**: `man 7 capabilities` - Linux privilege separation
- **Error handling**: `docs/error-handling.md` - error context and wrapping conventions

## Risks / Trade-offs

**strace overhead** → Monitoring is opt-in via `--monitor` flag. Users accept the performance hit when they need visibility.

**bwrap availability** → Document as hard requirement. Could add runtime check with helpful error message.

**Config mistakes expose sensitive files** → Default-deny helps. Auditability through explicit rules and monitoring.
