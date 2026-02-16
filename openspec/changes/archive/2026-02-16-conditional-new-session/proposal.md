## Why

Bwrap's `--new-session` prevents SIGWINCH delivery to sandboxed processes, breaking terminal resize for TUI applications. On Linux 6.2+, the kernel disables TIOCSTI by default (`/proc/sys/dev/tty/legacy_tiocsti = 0`), making `--new-session` redundant for its original purpose (CVE-2017-5226 mitigation). Skipping it on modern kernels restores terminal resize while maintaining security on older systems.

## What Changes

- Skip `--new-session` when the kernel already blocks TIOCSTI (`/proc/sys/dev/tty/legacy_tiocsti = 0`)
- Keep `--new-session` when TIOCSTI is enabled or the sysctl is absent (pre-6.2 kernels)
- Update security model documentation to reflect the conditional behavior

## Playbooks

### New Playbooks

_(none)_

### Modified Playbooks

- `sandboxing-filesystem`: Add use case for TUI applications receiving terminal resize signals.

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `sandbox`: BuildBwrapArgs conditionally includes `--new-session` based on kernel TIOCSTI status.

## Impact

- `internal/sandbox/` — `TIOCSTIBlocked()` function and conditional `--new-session` in `BuildBwrapArgs`
- `docs/security-model.md` — update terminal injection row to describe conditional mechanism
- No config format changes, no breaking changes, no new dependencies

## Security Impact

- **Bwrap invocation**: `--new-session` conditionally omitted. When omitted, the sandboxed process shares the host's session and has a controlling terminal.
- **TIOCSTI protection**: On modern kernels (6.2+), the kernel blocks TIOCSTI regardless of session boundaries (`/proc/sys/dev/tty/legacy_tiocsti = 0`). On older kernels, `--new-session` is still used.
- **Fail-safe**: If the sysctl is absent, unreadable, or has unexpected content, `--new-session` is used. The only path to omitting it is a positive `0` read from the kernel — false positives require a kernel bug.
- **Other sandbox boundaries unchanged**: No changes to permission checks, rule resolution, config parsing, mount namespace, or network isolation.
