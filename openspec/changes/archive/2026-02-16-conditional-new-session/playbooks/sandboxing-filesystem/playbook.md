## ADDED Use Cases

### Use Case: Sandboxed process receives terminal resize signal

On modern kernels where TIOCSTI is disabled, the sandbox skips `--new-session` so that SIGWINCH is delivered to the sandboxed process when the terminal is resized.

- **GIVEN** the kernel disables TIOCSTI (`/proc/sys/dev/tty/legacy_tiocsti` is `0`)
- **WHEN** the user runs a command that traps SIGWINCH inside the sandbox, and the terminal is resized
- **THEN** the command receives the SIGWINCH signal
