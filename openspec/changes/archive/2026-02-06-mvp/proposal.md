## Why

AI coding agents need filesystem sandboxing to prevent accidental or malicious access to sensitive files. Users need granular, per-project control over what an agent can read and write, with clear visibility into access attempts.

## What Changes

- New CLI tool `execave` that wraps commands in a bubblewrap sandbox
- Per-project JSON configuration defining filesystem access rules
- Optional access monitoring via strace (`--monitor`) for debugging and auditing
- Explicit-only filesystem access (sandbox starts empty, everything must be whitelisted)

## Capabilities

### New Capabilities

- `config`: Configuration file format and parsing (`./execave.json`)
- `sandbox`: Bubblewrap-based filesystem sandboxing with rule enforcement
- `monitor`: Optional strace-based access logging with rule attribution

### Modified Capabilities

(none - this is a new project)

## Security Impact

This change introduces security-critical components for a new sandbox system:

- **Permission checks**: Rule resolution engine determines access for every filesystem operation
- **Rule resolution**: Longest-prefix matching with permission hierarchy (none > ro > rw)
- **Sandbox boundaries**: Bubblewrap mount namespace isolation, default-deny filesystem
- **Config parsing**: JSON config validation and path normalization (user-controlled input)
- **Bwrap invocation**: Direct construction of bubblewrap command arguments

**Trust boundaries:**
- **User input → Config file**: Untrusted paths and rules parsed from JSON
- **Config → Sandbox**: Validated rules translated to bwrap mount arguments
- **Parent → Child process**: Sandboxed process runs with restricted filesystem view
- **Child → Parent (monitoring)**: strace intercepts syscalls for logging

**Threat model implications:**
- Config parsing bugs could allow sandbox escapes via malicious path traversal
- Rule resolution errors could grant unintended access to sensitive files
- Bwrap invocation bugs could weaken isolation (e.g., missing --unshare-all)
- Monitoring bugs could leak information but cannot weaken sandbox (strace wraps bwrap)

## Impact

- New Go CLI binary
- Requires bubblewrap (`bwrap`) installed on the system
- Requires strace for monitoring feature
- Linux-only (bubblewrap dependency)
