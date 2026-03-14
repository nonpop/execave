## ADDED Use Cases

### Use Case: Namespace escape via unshare blocked by seccomp

An adversary's command attempts to create a new user namespace inside the sandbox to escalate privileges. The seccomp filter blocks the `unshare` syscall with EPERM.

- **GIVEN** a config with rule `fs:ro:/usr`
- **WHEN** the user runs `execave -- <program-that-calls-unshare>`
- **THEN** the `unshare` syscall returns EPERM
- **AND** the process cannot create nested namespaces
