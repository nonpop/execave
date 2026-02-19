## 1. Enrich strace parser

- [x] 1.1 Add `parseResult` struct with fields: `pid`, `syscall`, `path`, `cwdHint`. Add `extractPid` method to `straceParser` that reads leading digits (with optional `[pid NNN]` format) from a strace line.
- [x] 1.2 Modify `atSyscallRegex` to capture AT_FDCWD vs fd number: change `(?:AT_FDCWD|\d+)` to `(AT_FDCWD|\d+)`. Update group indices in `parseLine` accordingly (former groups 2,3 become 3,4). When AT_FDCWD is matched and the `<path>` annotation is present, populate `cwdHint`.
- [x] 1.3 Change `parseLine` signature to return `(parseResult, bool)`. Update all call sites in `processStraceOutput`.
- [x] 1.4 Add `fchdirRegex` to `straceParser`. Handle fchdir as a third match attempt in `parseLine`, returning `parseResult{syscall: "fchdir", path: annotatedPath}`.

## 2. Cwd tracking in processStraceOutput

- [x] 2.1 Add `cwdByPid map[string]string` local variable in `processStraceOutput`. After setup phase ends, record `cwdHint` from parseResult into `cwdByPid[pid]` when non-empty.
- [x] 2.2 Handle `chdir`: when `parseResult.syscall == "chdir"`, update `cwdByPid[pid]` (absolute path recorded directly; relative path joined with existing entry; relative with no existing entry silently skipped). `continue` to skip processAccessEntry since chdir is not a file access.
- [x] 2.3 Handle `fchdir`: when `parseResult.syscall == "fchdir"`, update `cwdByPid[pid]` with the fd-annotated path and `continue`.
- [x] 2.4 Resolve bare-path relative paths: after cwd tracking updates, if the parsed path is relative and `cwdByPid[pid]` exists, join them before passing to `processAccessEntry`. Otherwise fall through to existing `handleRelativePath` → UNKNOWN.

## 3. Unit tests

- [x] 3.1 Test: cwd tracking resolves bare-path relative paths — synthetic strace with AT_FDCWD-annotated openat from pid, then `access(".git/config")` from same pid → produces absolute path entry with correct rule matching.
- [x] 3.2 Test: no cwd for pid → still unresolved — bare-path syscall from a pid with no prior AT_FDCWD/chdir/fchdir → UNKNOWN unresolved-relative-path.
- [x] 3.3 Test: per-pid cwd isolation — two pids with different cwds, bare-path calls resolve to different absolute paths.
- [x] 3.4 Test: cwd not tracked during setup phase — AT_FDCWD annotations during bwrap setup don't populate cwdByPid. Bare-path call from same pid after setup uses post-setup AT_FDCWD, not setup-phase one.
- [x] 3.5 Test: chdir updates tracked cwd — chdir with absolute path updates cwdByPid; subsequent bare-path call resolves correctly.
- [x] 3.6 Test: relative chdir joined with existing cwd — pid has cwd `/a`, does `chdir("b")`, then bare-path call resolves against `/a/b`.
- [x] 3.7 Test: relative chdir with no prior cwd is ignored — pid has no cwdByPid entry, does `chdir("sub")`, subsequent bare-path call still produces UNKNOWN.
- [x] 3.8 Test: fchdir updates tracked cwd — `fchdir(3</new/path>)` updates cwdByPid; subsequent bare-path call resolves correctly.
- [x] 3.9 Update `TestMonitor_UnresolvedRelativePath` comment — remove "older strace versions" claim, explain that bare-path syscalls (not AT_FDCWD annotation absence) are the primary cause.

## 4. E2E tests

- [x] 4.1 Test: bare-path relative accesses resolved in access log — run a command that produces bare-path `access()` calls with relative paths (use the custom C test program or `git status` in a non-worktree repo). Verify resolved absolute paths appear with correct rule matching instead of UNKNOWN.
- [x] 4.2 Test: unresolved relative path when no cwd tracked — verify that bare-path calls from a pid with no prior cwd produce UNKNOWN entries (this updates/extends the existing unresolved-relative-path E2E coverage if any).

## 5. Spec and doc updates

- [x] 5.1 Sync delta spec to `openspec/specs/monitor/spec.md` — replace "Path resolution for *at() syscalls" requirement with the broadened version covering cwd tracking.
- [x] 5.2 Update delta playbook to `openspec/playbooks/monitoring-access/playbook.md`.
- [x] 5.3 Check `docs/architecture.md` for monitor section references and update if needed.
