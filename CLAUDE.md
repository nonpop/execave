# Execave

Security-critical sandbox application. Subtle bugs cause significant harm.

**Go, Linux-only.** Uses bubblewrap (`bwrap`) and strace.

## Commands

```bash
CGO_ENABLED=0 go build -o ./bin/execave ./cmd/execave   # Build
go test ./...                             # Test
golangci-lint run --fix                   # Lint
./execave --config execave.json -- <command>
```

## Structure

- `cmd/execave/` - CLI entrypoint
- `internal/{config,fsrules,netrules,accesslog,sandbox,monitor,proxy,tunnel}/` - Core logic

## Documentation

- Every package and exported type, function, const, and var must have a godoc comment.
- Follow `docs/godoc-style.md` for godoc conventions (contracts over mechanisms, no repetition, placement rules).
- `docs/{architecture,security-model}.md` and `README.md` must be kept in sync with code.
- Use concise language; assume readers are experienced developers.
- Context section in `openspec/config.yaml` must be kept up to date. Also add, update, or remove rules to reflect changed project requirements.

## Security

- This is security-critical code. Write simple, auditable code and follow security best practices.
- Preconditions in godoc ("X must be Y") must be verified with panic checks at function entry.

**When modifying security-critical code** (permission checks, rule resolution, sandbox boundary, config parsing, bwrap invocation): explain why the change is safe and consider bypass scenarios. Read docs/security-model.md.

## Error Handling

- Follow conventions in `docs/error-handling.md`
- Error messages must read like a stack trace: operation → context → wrapped error
- No sentinel errors - use rich string errors with inline context
- **Impossible conditions must panic** (errors, unexpected values, violated invariants — anything that cannot happen in a correct program). Never swallow them with bare `return`, `continue`, `_ =`, or default branches.

## Testing

- Follow conventions in `docs/testing.md`
- Use testify: `require` for setup, `assert` for assertions
- **No assertion messages** — never pass a message argument to assert/require calls (`assert.Equal(t, want, got)` not `assert.Equal(t, want, got, "message")`)
- Strict TDD: failing test first, then implement
- Integration/E2E tests: black-box (`package_test`), public API only
- Unit tests: white-box (same package), direct access to internals
- Integration tests: every spec scenario must have a corresponding test in `<package>/integration_test.go`; update the test when the scenario changes, remove it when the scenario is removed
- E2E tests: every playbook use case must have a corresponding test in `test/e2e/<playbook_name>_test.go`; update the test when the use case changes, remove it when the use case is removed

## Git

Read-only. User handles staging, commits and pushes.
