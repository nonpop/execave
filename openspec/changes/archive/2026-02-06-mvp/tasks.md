## Security Task Requirements

**IMPORTANT**: All tasks marked `[SECURITY]` require reading `docs/security-model.md` before implementation. These tasks touch security-critical code paths (permission checks, rule resolution, sandbox boundaries, config parsing, bwrap invocation).

## 1. Project Setup

- [x] 1.1 Initialize Go module with `go mod init github.com/nonpop/execave`
- [x] 1.2 Create directory structure: `cmd/execave/`, `internal/sandbox/`, `internal/monitor/`, `internal/rules/`
- [x] 1.3 Add golangci-lint configuration

## 2. Configuration

- [x] 2.1 [SECURITY] Implement config file parsing (JSON with `rules` array)
- [x] 2.2 [SECURITY] Implement rule syntax validation (`fs:<permission>:<path>`)
- [x] 2.3 [SECURITY] Implement path normalization (resolve `..`, `.`, trailing slashes)
- [x] 2.4 [SECURITY] Implement relative path resolution (relative to config file directory)
- [x] 2.5 [SECURITY] Validate `fs:none` rules (more specific rules can override)
- [x] 2.6 [SECURITY] Reject duplicate paths (config error)

## 3. Rule Resolution

- [x] 3.1 [SECURITY] Implement rule matching (longest prefix match)
- [x] 3.2 [SECURITY] Implement default-deny behavior (no match → deny)
- [x] 3.3 [SECURITY] Implement symlink resolution to check target path permissions

## 4. Sandbox

- [x] 4.1 [SECURITY] Implement bubblewrap command builder
- [x] 4.2 [SECURITY] Configure empty filesystem base (default-deny)
- [x] 4.3 [SECURITY] Add essential system mounts (`/dev`, `/proc`)
- [x] 4.4 [SECURITY] Implement `fs:ro` bind mounts (read-only)
- [x] 4.5 [SECURITY] Implement `fs:rw` bind mounts (read-write)
- [x] 4.6 [SECURITY] Implement `fs:none` path hiding
- [x] 4.7 [SECURITY] Ensure denied access returns EACCES (not ENOENT)
- [x] 4.8 [SECURITY] Implement command execution and exit code propagation
- [x] 4.9 Export `BuildBwrapArgs()` for monitor integration

## 5. Access Monitor

- [x] 5.1 Implement strace wrapper for filesystem syscall tracing
- [x] 5.2 Map syscalls to READ/WRITE operation types
- [x] 5.3 Implement log format (`<OP> <PATH> <RESULT> <RULE>`)
- [x] 5.4 Implement rule attribution in log entries
- [x] 5.5 Implement log deduplication (unique (operation, path) pairs only)
- [x] 5.6 Support default log path (`./execave-access.log`)
- [x] 5.7 Support custom log path via `--monitor=<path>`
- [x] 5.8 Combine monitor with sandbox (strace wraps bwrap)

## 6. CLI

- [x] 6.1 Implement main CLI entrypoint with cobra or equivalent
- [x] 6.2 Add `--config` flag (default `./execave.json`)
- [x] 6.3 Add `--monitor` flag (optional, with optional path)
- [x] 6.4 Implement `--` separator for command arguments
- [x] 6.5 Add helpful error messages for missing config, invalid rules, missing bwrap
- [x] 6.6 Update `--monitor` to run sandbox+monitor combined mode

## 7. Testing

- [x] 7.1 Add unit tests for config parsing and validation
- [x] 7.2 Add unit tests for rule resolution logic
- [x] 7.3 Add integration tests for sandbox enforcement
- [x] 7.4 Add integration tests for monitor logging
- [x] 7.5 Add fuzz tests for config parsing
- [x] 7.6 Add integration tests for combined sandbox+monitor mode

## 8. Config File Protection

- [x] 8.1 [SECURITY] Pass config file path from CLI to sandbox builder
- [x] 8.2 [SECURITY] Implement `determineAccessLevel(configPath, rules)` to check what access the config file would have
- [x] 8.3 [SECURITY] Inject synthetic `fs:ro:<config-path>` rule when config would be rw
- [x] 8.4 [SECURITY] Print info message to stderr when access is reduced: `execave: config file forced read-only`
- [x] 8.5 [SECURITY] Add e2e test: config in rw directory is forced read-only
- [x] 8.6 [SECURITY] Add e2e test: config not mounted stays unmounted
- [x] 8.7 [SECURITY] Add e2e test: config already ro stays ro (no message)
