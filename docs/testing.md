# Testing Conventions

## Core Principles

1. **Strict TDD** — Write a failing test first, then implement.
2. **Test packaging** — Integration and E2E tests use `package_test` suffix (black-box, public API only). Unit tests live in the same package as the tested unit (white-box, direct access to internals).
3. **testify** — Use `require` for setup, `assert` for assertions.
4. **No assertion messages** — Omit the message parameter from assertions. If an assertion needs explanation, use a comment above it instead.

## Error Assertions

Use `assert.ErrorContains` over `assert.Error` to verify the *right* error occurred, not just *any* error. Choose distinctive substrings (e.g., `"config file not found"` not `"failed"`).

## Fuzz Testing

Use Go's native fuzz testing for input parsing and security-sensitive code. Seed corpus with both valid and invalid examples.

## Integration Tests

Integration tests verify spec scenarios against a package's public API. They live alongside unit tests in the package directory.

- **File**: `internal/<package>/integration_test.go` (uses `package <pkg>_test`)
- **1-1 mapping required**: Every spec scenario in `openspec/specs/<package>/spec.md` (or `openspec/changes/<change>/specs/<package>/spec.md`) must have exactly one corresponding integration test in `internal/<package>/integration_test.go`. The integration test file must contain only tests for spec scenarios — no additional tests.

Test name format — convert kebab-case names to PascalCase:

```
TestIntegration_<RequirementName>_<ScenarioName>
```

For example:
- Requirement: "Most specific rule wins", Scenario: "Specific ro overrides general rw" → `TestIntegration_MostSpecificRuleWins_SpecificRoOverridesGeneralRw`.

Unit tests (e.g., `TestParseRule_Valid` in `fsrules_test.go`) coexist in their own `*_test.go` files and use `package <pkg>` (white-box). Additional tests beyond spec scenarios belong in unit test files, not integration_test.go.

## End-to-End Tests

E2E tests live in `test/e2e/` and test the full binary.

### Openspec use case tests

- **1-1 mapping required**: Every use case in `openspec/playbooks/<playbook>/playbook.md` (or `openspec/changes/<change>/playbooks/<playbook>/playbook.md`) must have exactly one corresponding E2E test in `test/e2e/<playbook_name>_test.go`. The E2E test file must contain only tests for playbook use cases from that playbook — no additional tests.

- **File**: `test/e2e/<playbook_name>_test.go` (underscores, not hyphens)

Test name format — convert kebab-case names to PascalCase:

```
TestE2E_<PlaybookName>_<UseCaseName>
```

For example:
- Playbook: "sandboxing-filesystem", Use Case: "Run command with read-only system access" → `TestE2E_SandboxingFilesystem_RunCommandWithReadOnlySystemAccess` in `test/e2e/sandboxing_filesystem_test.go`.

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
