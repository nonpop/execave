## 1. Seccomp: export blocked syscall names

- [x] 1.1 Refactor `blockedSyscalls` from `[]uint32` to `[]blockedSyscall{name string, nr uint32}` in `internal/seccomp/seccomp.go`
- [x] 1.2 Add exported `BlockedSyscallNames() []string` function
- [x] 1.3 Update `Filter()` to extract numbers from struct slice
- [x] 1.4 Add `FilterPipeWithAllowed(allowed map[string]bool) (*os.File, error)` that excludes allowed names from blocklist before building BPF
- [x] 1.5 Tests: `TestBlockedSyscallNames` (returns expected names), `TestFilterPipeWithAllowed` (allowed syscall excluded from filter)

## 2. Access log: SYSCALL operation type

- [x] 2.1 Add `OperationSyscall OperationType = "SYSCALL"` and `RuleSeccomp = "seccomp"` constants to `internal/accesslog/accesslog.go`
- [x] 2.2 Tests: `TestLogger_SyscallEntryLogged`, `TestLogger_SyscallEntryDeduplicated`, `TestLogger_SyscallEntryNotFilteredByManagedPaths`

## 3. Config: syscall rule parsing

- [x] 3.1 Add `SyscallAllowRules []string` and `SyscallNologRules []string` fields to Config struct in `internal/config/config.go`
- [x] 3.2 Parse `syscall:allow:<name>` and `syscall:nolog:<name>` rules in `ParseRules` (route by `syscall:` prefix)
- [x] 3.3 Validate syscall names against `seccomp.BlockedSyscallNames()`; reject unknown names
- [x] 3.4 Reject duplicate names within allow rules and within nolog rules
- [x] 3.5 Tests: valid syscall rules accepted, invalid name rejected, non-blocked name rejected, duplicate allow rejected, duplicate nolog rejected, allow+nolog same name permitted, unknown action rejected
- [x] 3.6 Update config fuzz test if it covers rule parsing

## 4. Monitor: trace and log blocked syscalls

- [x] 4.1 Add `blockedSyscalls map[string]bool` and `allowedSyscalls map[string]bool` fields to Monitor struct; populate in `New()` from `seccomp.BlockedSyscallNames()` and config's `SyscallAllowRules` when `seccompFile != nil`
- [x] 4.2 Extend `buildStraceArgs` to append blocked+allowed syscall names to `-e trace=` expression when `blockedSyscalls` is non-nil
- [x] 4.3 Add `blockedSyscalls map[string]bool` field and fallback regex `^\d*\s*(\w+)\(` to `straceParser`; in `parseLine`, try fallback after existing regexes fail and check against blocked set
- [x] 4.4 In `processStraceLine`, intercept blocked/allowed syscalls before `resolveCWD`/`processAccessEntry`: log as SYSCALL/DENY/seccomp or SYSCALL/OK/syscall:allow:<name>
- [x] 4.5 Update `New()` signature to accept allowed syscalls; thread through from runner
- [x] 4.6 Tests: `TestBuildStraceArgs_WithBlockedSyscalls`, `TestBuildStraceArgs_WithoutBlockedSyscalls`, `TestProcessStraceLine_BlockedSyscall`, `TestProcessStraceLine_BlockedSyscall_FileGroup`, `TestProcessStraceLine_AllowedSyscall`

## 5. Logfilter: syscall nolog support

- [x] 5.1 Extend `IsNolog` in `internal/logfilter/logfilter.go` to handle SYSCALL entries: match target (syscall name) against `SyscallNologRules` set
- [x] 5.2 Tests: SYSCALL entry with matching nolog rule returns true, without returns false

## 6. Runner: thread config through to monitor

- [x] 6.1 Pass `SyscallAllowRules` from config to sandbox/seccomp (`FilterPipeWithAllowed`) and to monitor (`New`)
- [x] 6.2 Pass `SyscallNologRules` to logfilter context

## 7. Integration and E2E tests

- [x] 7.1 Monitor integration test: real strace execution with blocked syscall attempt produces SYSCALL entry
- [x] 7.2 Config integration test: `ParseRules` with syscall rules produces correct config
- [x] 7.3 E2E test for "View seccomp-denied syscall attempts" use case
- [x] 7.4 E2E test for "Selectively allow a blocked syscall" use case
- [x] 7.5 E2E test for "Invalid syscall name rejected" use case

## 8. Documentation

- [x] 8.1 Update `docs/security-model.md`: seccomp denials visible in access log; document `syscall:allow` trust implications
- [x] 8.2 Update `openspec/config.yaml` context section
