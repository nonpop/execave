## Context

The monitor processes strace output after the sandboxed process exits, writing an access log of filesystem operations. Currently, all accesses to paths within configured rules are logged regardless of whether the file exists. Programs routinely probe many nonexistent paths (dynamic linker search paths, config fallbacks, locale directories), creating noise that makes the log harder to use for debugging.

Current type involved:

- `monitor.logPathAccess` — writes a single log entry after managed-path and dedup checks

## Goals / Non-Goals

**Goals:**
- Reduce log noise by filtering out accesses to nonexistent files
- Keep the log useful for debugging ("what did the program actually touch?")

**Non-Goals:**
- Changing the log format
- Parsing strace return values (host-side stat is sufficient)

## Decisions

### 1. Host-side `os.Stat` in `logPathAccess`

Add an `os.Stat(path)` check in `logPathAccess`, after the managed-path and dedup checks. If `os.Stat` returns an error wrapping `os.ErrNotExist` AND the operation is a read, return nil (skip the entry). Write operations are always logged regardless of path existence. For any other `os.Stat` error, proceed with logging (fail-safe: when in doubt, log it). Placing the check after dedup avoids redundant stat calls for duplicate accesses.

**Why host-side stat?** The alternative is parsing `ENOENT` from strace return values, which requires extending the strace parser. Host-side stat is simpler. The paths in question are bind-mounted from the host, so host and sandbox views agree for paths governed by rules.

**Why not concern about TOCTOU?** The strace output is processed after the child exits. Files created and deleted during execution would show as nonexistent on host check, but this is an acceptable edge case — ephemeral files within a single sandbox run are rarely relevant to debugging.

### 2. Distinguish read and write operations

Filter nonexistent paths only for read operations. Read operations to nonexistent files are typically noise (library search paths, config fallbacks, locale probing). Write operations to nonexistent files represent the program's intent to create files, which is semantically different and valuable for debugging — users need to see what files the sandboxed program tried to create, even if the creation was denied.

### 3. Filter applies to direct paths and symlink targets

The existence check applies in `logPathAccess`, which is called for both direct path accesses and symlink resolution (hops and targets). A nonexistent symlink hop or target is also filtered (for read operations only).

## Risks / Trade-offs

**[TOCTOU for ephemeral files]** → Accepted. Files created and deleted during sandbox execution won't appear in the log. This is rare for short-lived sandboxed commands and acceptable for a debugging tool.

**[Directories always exist]** → No issue. Directory accesses (stat, getdents) hit paths that exist. The filtering primarily affects file probing (open, stat on nonexistent files).

**[`os.Stat` errors other than `ENOENT`]** → Fail-safe: if `os.Stat` fails for a reason other than nonexistence (permission denied, I/O error), proceed with logging. This matches the sandbox's default-deny model (see `docs/security-model.md`) — when in doubt, surface the entry rather than hide it.

**[Auditing concern]** → The access log is a debugging aid, not a security audit trail (see `docs/security-model.md`: "monitor too expensive for regular use, so syscall logs typically unavailable"). Sandbox enforcement is kernel-level and unaffected.
