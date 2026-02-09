# Execave

Security-critical sandbox application. Subtle bugs cause significant harm.

**Go, Linux-only.** Uses bubblewrap (`bwrap`) and strace.

## Commands

```bash
go build -o ./bin/execave ./cmd/execave   # Build
go test ./...                             # Test
golangci-lint run --fix                   # Lint
./execave --config execave.json -- <command>
```

## Structure

- `cmd/execave/` - CLI entrypoint
- `internal/{config,sandbox,monitor,rules}/` - Core logic

## Documentation

- Every package and exported type, function, const, and var must have a godoc comment.
- `docs/{architecture,security-model}.md` and `README.md` must be kept in sync with code.
- Use concise language; assume readers are experienced developers.
- Context section in `openspec/config.yaml` must be kept up to date. Also add, update, or remove rules to reflect changed project requirements.

## Security

- This is security-critical code. Write simple, auditable code and follow security best practices.
- If something "should never happen" but it happens anyway, panic.
- Preconditions in godoc ("X must be Y") must be verified with panic checks at function entry.

**When modifying security-critical code** (permission checks, rule resolution, sandbox boundary, config parsing, bwrap invocation): explain why the change is safe and consider bypass scenarios. Read docs/security-model.md.

## Error Handling

- Follow conventions in `docs/error-handling.md`
- Error messages must read like a stack trace: operation → context → wrapped error
- No sentinel errors - use rich string errors with inline context

## Testing

- Follow conventions in `docs/testing.md`
- Use testify: `require` for setup, `assert` for assertions
- Strict TDD: failing test first, then implement
- Black-box tests (`package_test`), internals via `export_test.go`
- E2E tests: every openspec scenario must have corresponding test

## Git

Read-only. User handles staging, commits and pushes.
