# Testing Conventions

## Core Principles

1. **Strict TDD** — Write a failing test first, then implement.
2. **Test packaging** — E2E tests and component tests use `package_test` suffix (black-box, public API only).
3. **testify** — Use `require` for setup, `assert` for assertions.
4. **No assertion messages** — Omit the message parameter from assertions. If an assertion needs explanation, use a comment above it instead.

## Error Assertions

Use `assert.ErrorContains` over `assert.Error` to verify the *right* error occurred, not just *any* error. Choose distinctive substrings (e.g., `"config file not found"` not `"failed"`).

## Fuzz Testing

Use Go's native fuzz testing for input parsing and security-sensitive code. Seed corpus with both valid and invalid examples.

## Strategy

**E2E tests** (`test/e2e/`) — source of truth. Each test documents a use case and verifies it against the real sandbox (compiled binary, real bwrap). Cover representatives of the happy path, edge cases, and error cases for each use case. For the critical config → sandbox path, test more exhaustively with various non-trivial configs and edge cases (e.g., configs with only a `net` section, overlapping rules, composition of multiple rule types).

**Component tests** (`internal/<pkg>/*_test.go`) — extend coverage where e2e would be too slow. Test a package's public API for cases like parsing edge cases, validation rules, or resolution combinatorics.

**Integration tests** — optional additional verification for critical internal boundaries (e.g., config → bwrap args) where catching a mismatch before e2e is valuable.

### TDD workflow

E2e tests describe the program's use cases. Strict TDD applies:
- **New behavior**: write e2e test first, see it fail, then implement
- **Changed behavior**: update e2e test first, see it fail against the old implementation, then change the code
- **Bug fix**: a bug is a missing or incorrect use case — write or fix the e2e test first, then fix the code
- This ensures every use case has a test and that tests actually verify the intended behavior

### E2E test guidelines

- Each test documents a use case — if a user wouldn't care about a change, it doesn't need a test
- Tests compile the binary and run it with real bwrap/strace
- Tests that verify CLI routing, flag handling, or error pipelines belong here
- Use given/when/then comments to make tests self-documenting
- Prefer table-driven tests when covering similar cases (e.g., multiple rule variants, multiple error conditions); each table entry is a sub-case of the same use case

### Component test guidelines

- Black-box: use `package_test` suffix, test only the public API — survives refactors
- Do not expand a package's public API for testing purposes, not even using the `export_test.go` pattern
- Cover cases that would be impractical to test end-to-end

## End-to-End Tests

E2E tests live in `test/e2e/` and test the full binary.

### Scenario DSL

Most E2E tests use a `scenario` builder that handles bwrap checks, temp dirs, config writing, and assertions.

```go
func TestE2E_Example_ReadOnlyAccess(t *testing.T) {
    s := newScenario(t)                        // checks bwrap, creates temp dir
    data := s.givenDir("data")                 // creates named subdirectory → testDir
    testFile := data.file("f.txt", "hello")    // creates file, returns path

    s.givenRules("fs:ro:" + data.String())     // prepends systemPaths(), writes config

    s.whenRun("cat", testFile)                 // runs execave with config
    s.thenExitCode(0)                          // asserts on last result
    s.thenStdoutContains("hello")
}
```

**`testDir`** — named `string` with path helpers:
- `dir.join("sub", "file")` — `filepath.Join`
- `dir.file("name", "content")` — creates file with parent dirs, returns path
- `dir.rel("sub/file")` — returns `~/`-shortened path for monitor assertions
- `"fs:rw:" + dir` — concatenation works because `testDir` is a `string`

**`scenario`** — unified test harness with Given/When/Then method prefixes:

Given (setup):
- `newScenario(t)` — checks bwrap, creates temp dir
- `s.givenDir("name")` — creates subdirectory, returns `testDir`
- `s.givenSymlink(target, link)` — creates symlink with parent dirs
- `s.givenRules(rules...)` — prepends `systemPaths()`, writes config
- `s.givenRulesOnly(rules...)` — writes config without `systemPaths()` (error-path tests)
- `s.givenRulesInDir(dir, rules...)` — writes config in specific directory
- `s.givenRawConfig(content)` — writes raw TOML content
- `s.givenCurl()` / `s.givenPython3()` / `s.givenGcc()` — tool checks
- `s.givenHTTPServer(body)` / `s.givenHTTPSServer(body)` — test servers returning `testServer`

When (action):
- `s.whenRun(args...)` — runs execave with config, resets result
- `s.whenRunWithDefaultConfig(workDir, args...)` — runs without `--config`
- `s.whenRunTextLog(monitorArg, args...)` — runs with `--monitor=<file or ->`
- `s.whenRunTextLogWithFlags(monitorArg, flags, args...)` — text log with extra flags

Then (assertions on last `whenRun*` result):
- `s.thenExitCode(n)` / `s.thenExitCodeNonZero()`
- `s.thenStdoutContains(sub)` / `s.thenStderrContains(sub)` / `s.thenStderrNotContains(sub)`
- `s.thenFileContains(path, sub)`
- `s.thenStderrHasEntry(substrings...)` — asserts a single stderr line contains all given substrings

**Edge cases** — some tests still use low-level helpers directly when they need raw `exec.Cmd` access (e.g., SIGWINCH test, long-running process tests).

## Security Testing

Always test:

1. **Fail-closed behavior** — unknown or invalid states must deny access
2. **Directory boundaries** — `/home/user2` must not match rule for `/home/user`
