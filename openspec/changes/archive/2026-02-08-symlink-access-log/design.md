## Context

The monitor logs filesystem accesses by parsing strace output and checking each path against the rule resolver. `CheckAccess` resolves symlinks internally — it checks the symlink is readable, then checks the resolved target with the requested operation. But it returns a single `AccessResult`, so the monitor logs one entry against the original (symlink) path with the target's access decision. This produces two problems:

1. **Confusing log entries:** `READ /etc/resolv.conf DENY no-matching-rule` when the rule for `/etc/resolv.conf` exists but its symlink target does not.
2. **Incorrect symlink resolution:** `CheckAccess` uses `filepath.EvalSymlinks` on the host, which resolves the entire path in one shot. This skips intermediate hops in symlink chains (A→B→C — only A and C are checked, not B) and doesn't check symlinks in intermediate path components (`/usr/lib/foo.so` where `/usr/lib` → `/usr/lib64`). In bwrap, the kernel resolves symlinks step by step through the mount namespace — if any intermediate path is not mounted, the resolution fails with ENOENT.

Current types involved:

- `rules.AccessResult{Allowed bool, Rule *config.Rule}` — single result from `CheckAccess`
- `monitor.processAccessEntry` — logs one entry per strace-reported path

## Goals / Non-Goals

**Goals:**
- Resolve symlink chains step by step, matching kernel behavior inside bwrap's mount namespace
- Make the full resolution chain visible in the access log (one entry per step + final target)
- Preserve existing `AccessResult.Allowed` semantics so callers checking only `.Allowed` are unaffected

**Non-Goals:**
- Symlink-specific dedup behavior beyond extending the existing `(op, path)` dedup to each hop and the target

## Decisions

### 1. Replace `filepath.EvalSymlinks` with component-by-component path walk

Instead of resolving the entire path at once on the host, `CheckAccess` walks the path component by component, matching how bwrap and the kernel handle symlinks:

1. Split path into components: `/usr/lib/foo.so` → `["usr", "lib", "foo.so"]`
2. Starting from `/`, accumulate path one component at a time
3. `os.Lstat(accumulated)` — check if the current component is a symlink
4. If symlink, distinguish two cases:
   - **Rule boundary** (symlink path exactly matches a rule path): bwrap resolves this at mount time — skip resolution, treat as regular directory/file, continue
   - **Within a rule** (symlink path is a descendant of a rule, or has no matching rule): kernel resolves at access time — `os.Readlink`, record hop, check rule, replace:
     - Absolute target: restart resolution from root with remaining components appended
     - Relative target: resolve against parent directory, continue
     - No matching rule or not readable: chain breaks, deny
5. If not a symlink: advance to next component
6. After all components: the accumulated path is the fully resolved path

This correctly handles:
- **Rule-target symlinks** (`/etc/resolv.conf` → `stub-resolv.conf`, rule `fs:ro:/etc/resolv.conf`): bwrap mounts the target at the symlink path → skip resolution → rule matches original path → OK
- **Symlinks within mounts** (`/foo/bar/link` → `/secret/data`, rule `fs:ro:/foo/bar`): kernel resolves at access time → resolve and check target → DENY if target has no rule
- **Multi-hop chains**: each hop checked individually
- **Symlinks in intermediate components** (`/usr/lib` → `/usr/lib64`): resolved during walk

**Depth limit:** 40, matching the Linux kernel's `MAXSYMLINKS`. The counter spans the entire walk (not per-component). Exceeding the limit is treated as a denial (the kernel returns ELOOP). When the depth limit is exceeded, the monitor logs the denied hop with the dedicated rule string `symlink-depth-limit-exceeded`.

**Non-existent paths:** If `os.Lstat` returns `ENOENT`, the remaining path is treated as literal (no more symlink resolution). This handles paths that don't exist on the host — they won't exist in the sandbox either, so symlink resolution is moot.

**Errors other than `ENOENT`:** Treated as resolution failure — deny access. Fail-closed, matching the sandbox's default-deny model (see `docs/security-model.md`).

### 2. Expose symlink chain via `SymlinkChain` on `AccessResult`

```go
// SymlinkChain captures each hop in a symlink resolution chain.
type SymlinkChain struct {
    Hops         []SymlinkHop
    ResolvedPath string       // Final target path (clean, absolute)
}

// SymlinkHop represents one symlink in the resolution chain.
type SymlinkHop struct {
    Path    string       // The symlink path (clean, absolute)
    Allowed bool         // Was this hop readable?
    Rule    *config.Rule // Matching rule, or nil
}
```

`AccessResult.Symlink` is non-nil when the walk resolved at least one symlink (i.e., encountered a symlink within a rule, not at a rule boundary). The main `AccessResult.Allowed` and `.Rule` fields represent the **final target** access decision. If the chain breaks at any hop (denied or no rule), `Allowed` is false, `Rule` is nil (target was never evaluated), and `ResolvedPath` is empty.

**Why a slice of hops?** Each hop is a separate access that the monitor needs to log independently. A single struct can't represent multi-hop chains.

**Why not have the monitor resolve symlinks and call `CheckAccess` per hop?** The monitor would need to detect symlinks, walk the chain, and resolve targets itself before calling `CheckAccess` for each — duplicating the resolution logic that `CheckAccess` already encapsulates.

### 3. Monitor emits one log entry per hop plus the final target

When `result.Symlink` is non-nil, `processAccessEntry` writes:

1. For each hop in `Symlink.Hops`: `READ <hop-path> <OK|DENY> <rule>` — always READ since reading the symlink is required to resolve it, regardless of the original operation
2. If all hops were readable: `<OP> <resolved-path> <OK|DENY> <rule>` — the final target access with the original operation

Each hop and the target go through their own `isFirstEntryFor` dedup check and `isManagedPath` filtering independently.

### 4. No changes to fuzz tests

Fuzz-generated paths are random strings that don't exist as real symlinks on disk. `os.Lstat` returns `ENOENT`, so the walk treats them as non-symlinks and `Symlink` will be nil. Existing invariants hold without modification.

### 5. Symlinks through managed paths produce UNKNOWN result

The component walk runs on the host filesystem. Managed paths (`/dev`, `/proc`, `/tmp`) are backed by sandbox-internal filesystems (devtmpfs, procfs, tmpfs) that don't exist on the host. When a symlink target falls under a managed path, the host can't follow it — the target only exists inside the sandbox's mount namespace.

When `resolvePathComponents` detects that a symlink target is under a managed path, it stops resolution and marks the chain as `Unresolvable`. `CheckAccess` returns `Uncertain: true, Allowed: false`. The monitor logs the original path with result `UNKNOWN` and rule `symlink-target-unresolvable`.

New fields added to existing types:

```go
type SymlinkChain struct {
    Hops               []SymlinkHop
    ResolvedPath       string // Empty if unresolvable or depth limit exceeded
    Unresolvable       bool   // True if chain entered a managed path
    DepthLimitExceeded bool   // True if chain exceeded MAXSYMLINKS
}

type AccessResult struct {
    Allowed   bool
    Rule      *config.Rule
    Symlink   *SymlinkChain
    Uncertain bool // True if result could not be determined
}
```

Managed paths are passed to the resolver via `Config.ManagedPaths`, populated from `sandbox.ManagedDirs` during config loading.

**Why not attempt resolution anyway?** The host path (e.g., `/tmp/target.txt`) may exist but contain different content than the sandbox's tmpfs — following it would produce incorrect results. Reporting UNKNOWN is honest and fail-safe.

**Future direction:** Running the monitor inside the sandbox (with UDS communication back to execave) would eliminate the namespace mismatch entirely, allowing full resolution of all symlink chains.

## Risks / Trade-offs

**TOCTOU between strace capture and path walk:** The walk runs on the host filesystem after command execution. If symlinks changed during execution, the walk may not reflect what the kernel saw. This is inherent to the monitor's post-hoc analysis model. The sandbox itself is not affected — bwrap's mount namespace is the security boundary, not the monitor (see "Symlinks can't escape" in `docs/security-model.md`).

**More `Lstat` calls than `EvalSymlinks`:** The component walk does one `Lstat` per path component (plus `Readlink` for symlinks), versus a single `EvalSymlinks` call. For a typical path like `/usr/lib/x86_64-linux-gnu/libc.so.6` that's ~5 `Lstat` calls. This runs during post-execution log processing, so the overhead is negligible.

**Dedup key mismatch for symlink READ vs original operation:** If a symlink path is accessed first for WRITE then for READ, the hop's READ entry could appear twice (once from each dedup key). This matches existing behavior for non-symlink paths — different operations produce separate log entries — and is acceptable for an audit log.
