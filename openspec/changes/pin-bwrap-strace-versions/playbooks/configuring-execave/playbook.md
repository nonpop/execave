## ADDED Use Cases

### Use Case: Incompatible bwrap version blocks execution

The user has a bwrap binary that is either older than the pinned version or a major version bump. Execave refuses to run to prevent silent misbehaviour from an untested binary.

- **GIVEN** bwrap is installed but its version is older than 0.11.0, or is ≥1.0.0
- **WHEN** the user runs `execave -- <command>`
- **THEN** execave exits before running the command
- **AND** an error message is printed to stderr identifying the installed version and the compatibility problem

### Use Case: Incompatible strace version blocks monitoring

The user has a strace binary that is either older than the pinned version or a major version bump. Execave refuses to start monitoring to prevent silent access-log corruption from an untested binary.

- **GIVEN** strace is installed but its version is older than 6.18, or is ≥7.0
- **WHEN** the user runs `execave --monitor -- <command>`
- **THEN** execave exits before running the command
- **AND** an error message is printed to stderr identifying the installed version and the compatibility problem

### Use Case: Newer minor-version bwrap prints warning but continues

The user has a newer bwrap from the same 0.x series (e.g., 0.12.0). Execave warns that the version is untested but proceeds, since minor bumps in bwrap have historically been additive.

- **GIVEN** bwrap is installed and its version is higher than 0.11.x but still within the 0.x series
- **WHEN** the user runs `execave -- <command>`
- **THEN** execave prints a warning to stderr identifying the installed version
- **AND** the command runs normally in the sandbox

### Use Case: Newer minor-version strace prints warning but continues

The user has a newer strace from the same 6.x series (e.g., 6.19). Execave warns that the version is untested but proceeds, since minor bumps in strace 6.x have not changed the output format that execave parses.

- **GIVEN** strace is installed and its version is higher than 6.18 but still within the 6.x series
- **WHEN** the user runs `execave --monitor -- <command>`
- **THEN** execave prints a warning to stderr identifying the installed version
- **AND** the command runs normally with monitoring enabled
