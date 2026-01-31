# Testing Conventions

## Core Principles

1. **Strict TDD** — Write a failing test first, then implement.
2. **Black-box testing** — Use `package_test` suffix. Test public API, not implementation.
3. **testify** — Use `require` for setup, `assert` for assertions.
4. **No assertion messages** — Omit the message parameter from assertions. If an assertion needs explanation, use a comment above it instead.

## Error Assertions

Use `assert.ErrorContains` over `assert.Error` to verify the *right* error occurred, not just *any* error. Choose distinctive substrings (e.g., `"config file not found"` not `"failed"`).

## Exposing Internals

When you must test unexported functions, expose them through `export_test.go`:

```go
// export_test.go (inside the package, only compiled during testing)
package config

var ParseRule = parseRule
```

Then test from the `_test` package as usual.

## Fuzz Testing

Use Go's native fuzz testing for input parsing and security-sensitive code. Seed corpus with both valid and invalid examples.

## End-to-End Tests

E2E tests live in `test/e2e/` and test the full binary.

### Openspec scenario tests

**Every openspec scenario must have a corresponding E2E test.**

Test names must match scenario names from the openspec specs. Format:

```
TestE2E_<Spec>_<ScenarioNameInPascalCase>
```

For example, "Write denied on read-only path" in sandbox/spec.md → `TestE2E_Sandbox_WriteDeniedOnReadOnlyPath`.

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
