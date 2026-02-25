## ADDED Requirements

### Requirement: Seccomp filter integration

When seccomp is enabled (default), `Run()` SHALL create a seccomp filter pipe, add it to `cmd.ExtraFiles`, and insert `--seccomp <fd>` into the bwrap arguments before the `--` separator. The fd number SHALL be 3 (first ExtraFile). When `allowAllSyscalls` is true, no seccomp filter SHALL be applied.

#### Scenario: Seccomp enabled by default
- **WHEN** `New()` is called with `allowAllSyscalls=false`
- **AND** `Run()` is called
- **THEN** the bwrap command includes `--seccomp 3` before `--`
- **AND** `cmd.ExtraFiles` contains the seccomp filter pipe

#### Scenario: Seccomp disabled with flag
- **WHEN** `New()` is called with `allowAllSyscalls=true`
- **AND** `Run()` is called
- **THEN** the bwrap command does NOT include `--seccomp`
- **AND** `cmd.ExtraFiles` is empty

### Requirement: Seccomp arg insertion helper

The sandbox package SHALL export `InsertSeccompArg(args []string, fd int) []string` which inserts `--seccomp <fd>` before the `--` separator in bwrap args. This is used by both `sandbox.Run()` and the monitor for consistent arg manipulation.

#### Scenario: Seccomp arg inserted before separator
- **WHEN** `InsertSeccompArg(["--unshare-all", "--", "bash"], 3)` is called
- **THEN** it returns `["--unshare-all", "--seccomp", "3", "--", "bash"]`
