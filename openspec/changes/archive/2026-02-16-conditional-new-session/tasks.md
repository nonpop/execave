## 1. TIOCSTI Detection

- [x] 1.1 [SECURITY] Implement `tiocSTIBlocked()` in `internal/sandbox/` — reads `/proc/sys/dev/tty/legacy_tiocsti`, returns `true` only when content is `0`, `false` for all other cases
- [x] 1.2 Write unit tests for `tiocSTIBlocked()` (white-box, same package) — covers: sysctl contains `0`, contains `1`, file absent, unexpected content

## 2. Conditional `--new-session`

- [x] 2.1 [SECURITY] Modify `BuildBwrapArgs` to call `tiocSTIBlocked()` and conditionally include `--new-session`
- [x] 2.2 Write integration tests for conditional `--new-session` in `BuildBwrapArgs` — covers: new-session omitted when TIOCSTI blocked, included when not blocked, included when sysctl absent/unreadable

## 3. E2E Tests

- [x] 3.1 Write E2E test: sandboxed process receives SIGWINCH on modern kernel (trap SIGWINCH inside sandbox, resize terminal, verify signal received)

## 4. Documentation

- [x] 4.1 Update `docs/security-model.md` — change terminal injection row to describe conditional mechanism (kernel TIOCSTI disabling + `--new-session` fallback)
