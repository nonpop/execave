## Context

The monitor parses strace output to log filesystem access. Strace's `-y` flag annotates fd arguments with resolved paths, so `openat(AT_FDCWD</home/user/project>, ".git/config")` produces an absolute path via `filepath.Join(fdPath, relPath)`. However, bare-path syscalls like `access(".git/config")` have no fd argument, so strace cannot annotate them. These currently produce `UNKNOWN unresolved-relative-path` entries.

Empirically verified: `git status` in a normal (non-worktree) repo produces ~9 bare-path `access(".git/...")` calls per invocation. Modern glibc wraps `stat()` into `newfstatat(AT_FDCWD, ...)`, but `access()` remains a bare syscall.

Current data flow:

```
strace line → parseLine(line) → (syscall, path, ok)
                                        │
                              processStraceOutput
                                        │
                              processAccessEntry(syscall, path, line)
                                        │
                                  ┌─────┴──────┐
                                  │ abs path?  │
                                  └─────┬──────┘
                                   yes/   \no
                                    /       \
                            checkAccess   handleRelativePath → UNKNOWN
```

## Goals / Non-Goals

**Goals:**
- Resolve bare-path relative syscalls to absolute paths using tracked per-pid cwd.
- Track cwd from three sources: AT_FDCWD annotations, `chdir()`, and `fchdir()`.
- Maintain existing fallback: UNKNOWN when no cwd is known for a pid.
- Skip cwd tracking during bwrap setup phase (host namespace cwd, not sandbox cwd).

**Non-Goals:**
- Propagating cwd from parent to child on clone/fork. Children get their cwd from their first AT_FDCWD annotation, chdir, or fchdir. The dynamic linker emits AT_FDCWD-annotated calls almost immediately after exec, so the gap is minimal.
- Tracking cwd for non-file syscalls.

## Decisions

### 1. Enrich parseLine return type with parseResult struct

`parseLine` currently returns `(syscall, path, ok)`. Change it to return `(parseResult, bool)` where `parseResult` has fields: `pid`, `syscall`, `path`, `cwdHint`. The `bool` stays a separate return value — it's a parsing success indicator, not a property of the result.

- `pid`: extracted from the leading digits of the strace line (e.g., `12345 openat(...)` → `"12345"`).
- `cwdHint`: populated when the AT_FDCWD fd has a `<path>` annotation. This is the cwd at the time of the call.

**Why a struct?** The pid and cwdHint are naturally produced during regex matching in parseLine. Extracting them separately would mean double-parsing lines or awkward regex duplication.

**Alternative considered:** Extract pid in processStraceOutput and pass cwd tracking as a separate concern. Rejected because cwdHint comes from the AT_FDCWD annotation inside the atSyscallRegex match — it's inherently part of parsing.

### 2. Modify atSyscallRegex to capture AT_FDCWD vs fd number

Change `(?:AT_FDCWD|\d+)` to `(AT_FDCWD|\d+)` to make it a capturing group. This lets parseLine distinguish AT_FDCWD (cwd hint source) from numeric fds (not a cwd hint). Groups shift: former group 2 (fdpath) becomes group 3, former group 3 (path) becomes group 4.

### 3. Track cwd in processStraceOutput from three sources

Add a local `cwdByPid map[string]string` in processStraceOutput. After the setup phase ends, update it from:

1. **AT_FDCWD annotations** (cwdHint from parseResult): most common source, arrives via dynamic linker openat calls right after exec.
2. **chdir(path)**: parseLine matches this via `syscallRegex` (returns `parseResult{syscall: "chdir", path: "/path"}`). Intercept in processStraceOutput before processAccessEntry. Handle both absolute and relative paths (join with existing cwdByPid entry).
3. **fchdir(fd\<path\>)**: parseLine matches this via `fchdirRegex` as a third attempt (returns `parseResult{syscall: "fchdir", path: annotatedPath}`). The `fchdirRegex` is needed because fchdir's argument is `fd<annotation>` not `"quoted-path"`. Intercept in processStraceOutput alongside chdir.

### 4. Add extractPid helper to straceParser

New method that reads leading digits from a strace line (the `[pid NNN]` or bare `NNN` prefix). Returns empty string when no pid prefix exists (single-process trace). Used by processStraceOutput to key the cwdByPid map.

### 5. Resolve relative paths before processAccessEntry

In processStraceOutput, after cwd tracking updates, if the parsed path is relative and cwdByPid has an entry for the pid, join them. Otherwise, fall through to processAccessEntry which hits handleRelativePath → UNKNOWN as before.

### 6. No cwd tracking during setup phase

During the bwrap setup phase (`inSetup == true`), AT_FDCWD annotations and chdir calls reflect the host namespace, not the sandboxed process. Recording them would produce wrong cwd entries. Skip all cwd tracking while `inSetup` is true.

After the transition (user command's execve), the dynamic linker immediately emits AT_FDCWD-annotated openat calls, establishing the correct cwd for the pid.

## Risks / Trade-offs

**[Stale cwd after chdir to relative path with no prior cwd]** → If a pid does `chdir("subdir")` before any AT_FDCWD annotation, we can't resolve it to absolute. The chdir is silently skipped and any subsequent bare-path calls fall through to UNKNOWN. This is the same as the current behavior — no regression.

**[Clone/fork children have no inherited cwd]** → A new pid from fork may do bare-path calls before its first AT_FDCWD annotation. Falls through to UNKNOWN. Documented as known limitation. Can be addressed later by parsing clone return values if needed.

**[Logging accuracy vs sandbox enforcement]** → Cwd tracking only affects the audit log, not sandbox enforcement (bwrap handles that). A wrong cwd would produce an incorrect log entry (path matched against wrong absolute path). This is strictly a logging accuracy concern, not a security bypass. bwrap still enforces real permissions regardless.
