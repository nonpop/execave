## ADDED Requirements

### Requirement: Seccomp file fd plumbing

When a seccomp file is provided, `Monitor.Run()` SHALL append it to `cmd.ExtraFiles` after the strace pipe (making it fd 4) and insert `--seccomp 4` into the bwrap args before the `--` separator. The seccomp file SHALL be closed after the child process starts. When no seccomp file is provided, no seccomp-related changes SHALL be made.

#### Scenario: Seccomp file added as fd 4
- **WHEN** Monitor is created with a non-nil seccomp file
- **AND** `Run()` is called
- **THEN** `cmd.ExtraFiles` contains `[straceW, seccompFile]`
- **AND** the bwrap args include `--seccomp 4` before `--`

#### Scenario: No seccomp file means no seccomp args
- **WHEN** Monitor is created with a nil seccomp file
- **AND** `Run()` is called
- **THEN** `cmd.ExtraFiles` contains only `[straceW]`
- **AND** the bwrap args do NOT include `--seccomp`
