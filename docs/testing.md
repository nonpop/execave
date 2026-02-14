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
- **Every spec scenario must have a corresponding integration test.**

Test name format — convert kebab-case names to PascalCase:

```
TestIntegration_<RequirementName>_<ScenarioName>
```

For example:
- Requirement: "Most specific rule wins", Scenario: "Specific ro overrides general rw" → `TestIntegration_MostSpecificRuleWins_SpecificRoOverridesGeneralRw`.

Unit tests (e.g., `TestParseRule_Valid` in `fsrules_test.go`) coexist in their own `*_test.go` files and use `package <pkg>` (white-box).

## End-to-End Tests

E2E tests live in `test/e2e/` and test the full binary.

### Openspec use case tests

**Every playbook use case must have a corresponding E2E test.**

- **File**: `test/e2e/<playbook_name>_test.go` (underscores, not hyphens)

Test name format — convert kebab-case names to PascalCase:

```
TestE2E_<PlaybookName>_<UseCaseName>
```

For example:
- Playbook: "sandboxing-filesystem", Use Case: "Run command with read-only system access" → `TestE2E_SandboxingFilesystem_RunCommandWithReadOnlySystemAccess` in `test/e2e/sandboxing_filesystem_test.go`.

### Helpers

```go
// Dependency checks
failIfNoBwrap(t)
failIfNoStrace(t)

// Config
configPath := writeConfig(t, []string{"fs:ro:/usr", "fs:rw:/home"})
writeConfigInDir(t, dir, []string{"fs:ro:/usr"})
rules := append(systemPaths(), "fs:rw:/home/user/project")

// Running execave
result := runExecave(t, workDir, "--config", configPath, "--", "ls", "-la")
// result has: Stdout, Stderr, ExitCode

// Assertions
assertExitCode(t, result, 0)
assert.Contains(t, result.Stdout, "expected")
assert.Contains(t, result.Stderr, "error message")
assertLogExists(t, logPath)
assertLogNotExists(t, logPath)
assertLogContains(t, logPath, "pattern")

// File setup
createFile(t, path, "content")
createSymlink(t, target, link)
```

## Security Testing

Always test:

1. **Fail-closed behavior** — unknown or invalid states must deny access
2. **Directory boundaries** — `/home/user2` must not match rule for `/home/user`
