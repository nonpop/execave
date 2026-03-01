## 1. Seccomp filter package

- [x] 1.1 Create `internal/seccomp/seccomp.go` with `Filter() []byte` and `FilterPipe() (*os.File, error)`. Build BPF deny-list: arch check → syscall checks → ALLOW/ERRNO(EPERM)/KILL. Use `unix.SockFilter` and `encoding/binary.NativeEndian`. Define blocked syscall list with `unix.SYS_*` constants.
- [x] 1.2 Create `internal/seccomp/seccomp_test.go`. Unit tests: filter byte length matches expected instruction count, arch check is first instruction, each blocked syscall is present in the filter, FilterPipe returns readable file with correct content.

## 2. Sandbox integration

- [x] 2.1 Add `allowAllSyscalls bool` param to `sandbox.New()`. Add `SeccompEnabled() bool` method. Export `InsertSeccompArg(args []string, fd int) []string` helper.
- [x] 2.2 In `sandbox.Run()`: if seccomp enabled, call `seccomp.FilterPipe()`, set `cmd.ExtraFiles = []*os.File{pipe}`, call `InsertSeccompArg(bwrapArgs, 3)`.
- [x] 2.3 Update sandbox unit tests: verify `--seccomp 3` present/absent in bwrap args based on `allowAllSyscalls`.
- [x] 2.4 Add sandbox integration tests: run bwrap with seccomp filter, verify blocked syscall returns EPERM; run without filter, verify no EPERM from seccomp.

## 3. Monitor integration

- [x] 3.1 Add `seccompFile *os.File` param to `monitor.New()`. In `Run()`: if seccompFile non-nil, append to ExtraFiles after strace pipe, call `InsertSeccompArg(bwrapArgs, 4)`.
- [x] 3.2 Update monitor tests for new `New()` signature. Add tests: seccomp file plumbed as fd 4 when provided, no seccomp args when nil.

## 4. Runner integration

- [x] 4.1 Add `allowAllSyscalls bool` param to `runner.New()`. Add `SetAllowAllSyscalls(bool)` method (mutex-protected). In `Start()`: if seccomp enabled, call `seccomp.FilterPipe()` and pass to `monitor.New()`.
- [x] 4.2 Update runner tests for new constructor signature.

## 5. CLI flag

- [x] 5.1 Add `--allow-all-syscalls` bool flag to root command in `cmd/execave/main.go`. Thread through to `sandbox.New()` (direct path) and `runner.New()` (monitored path).

## 6. Documentation

- [x] 6.1 Update `docs/security-model.md`: add seccomp row to guarantees table, add to security-critical code table, add `--allow-all-syscalls` to limitations.
- [x] 6.2 Update `docs/architecture.md` if it references security layers.

## 7. E2E tests

- [x] 7.1 Add E2E test: default seccomp blocks a dangerous syscall (EPERM).
- [x] 7.2 Add E2E test: `--allow-all-syscalls` disables seccomp filtering.
- [x] 7.3 Add E2E test: namespace escape via unshare blocked by seccomp.
