## 1. Core Version Check Logic

- [x] 1.1 Write failing unit tests for `parseBwrapVersion` (parses `bwrap X.Y.Z` from first line, returns `[3]int`, errors on unparseable input)
- [x] 1.2 Write failing unit tests for `parseStraceVersion` (extracts first `MAJOR.MINOR` match from any line, returns `[2]int`, errors on no match)
- [x] 1.3 Write failing unit tests for `bwrapCompatLevel` covering all tier boundaries: `0.10.x` → error, `0.11.0` → ok, `0.11.5` → ok, `0.12.0` → warn, `0.99.9` → warn, `1.0.0` → error
- [x] 1.4 Write failing unit tests for `straceCompatLevel` covering all tier boundaries: `6.17` → error, `6.18` → ok, `6.19` → warn, `6.99` → warn, `7.0` → error
- [x] 1.5 Create `internal/sandbox/versions.go` with `PinnedBwrapVersion`, `PinnedStraceVersion`, `CheckBwrapVersion`, `CheckStraceVersion`, and unexported helpers — make tests pass

## 2. Integration — Sandbox

- [x] 2.1 Write failing integration test: `Sandbox.Run` with a fake bwrap at incompatible version (older or major bump) returns an error
- [x] 2.2 Write failing integration test: `Sandbox.Run` with a fake bwrap at warn-tier version prints warning to stderr and continues
- [x] 2.3 Add `CheckBwrapVersion` call in `sandbox.Sandbox.Run()` after `ResolveBwrap()` — make tests pass

## 3. Integration — Runner

- [x] 3.1 Write failing integration test for `runner`: incompatible strace version causes monitored run to return error
- [x] 3.2 Write failing integration test for `runner`: warn-tier strace version prints warning and continues
- [x] 3.3 Write failing integration test for `runner`: incompatible bwrap version in sandboxed-monitored run returns error
- [x] 3.4 Add `CheckStraceVersion` call in `runner.runMonitored()` after `ResolveStrace()` — make tests pass
- [x] 3.5 Add `CheckBwrapVersion` call in `runner.buildSandboxedMonitor()` after `ResolveBwrap()` — make tests pass

## 4. E2E Tests

- [x] 4.1 Add E2E test for "incompatible bwrap version blocks execution" use case (fake bwrap in PATH that outputs wrong version → execave exits with error)
- [x] 4.2 Add E2E test for "incompatible strace version blocks monitoring" use case
- [x] 4.3 Add E2E test for "newer minor-version bwrap prints warning but continues" use case
- [x] 4.4 Add E2E test for "newer minor-version strace prints warning but continues" use case

## 5. Docs

- [x] 5.1 Update `README.md` to document pinned bwrap/strace versions in the requirements section
- [x] 5.2 Update `docs/architecture.md` to mention version pinning and startup checks
- [x] 5.3 Mark "require fixed bwrap/strace versions?" as done in `docs/scratchpad/todo.md`
- [x] 5.4 Add `PinnedBwrapVersion` and `PinnedStraceVersion` to the context section in `openspec/config.yaml`
