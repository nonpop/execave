## ADDED Requirements

### Requirement: bwrap version check

CheckBwrapVersion SHALL run `bwrap --version`, parse the version string, and classify it against the pinned version 0.11.0.

- OK tier (`0.11.x`): return `("", nil)`.
- WARN tier (`0.12.x` through `0.99.x`): return `(warning, nil)` where warning describes the version mismatch.
- ERROR tier (`< 0.11.0` or `>= 1.0.0`): return `("", error)` where error describes the incompatibility.

#### Scenario: Exact pinned version — OK
- **WHEN** bwrap reports version `0.11.0`
- **THEN** CheckBwrapVersion returns `("", nil)`

#### Scenario: Higher patch, same minor — OK
- **WHEN** bwrap reports version `0.11.5`
- **THEN** CheckBwrapVersion returns `("", nil)`

#### Scenario: Higher minor, same 0.x major — WARN
- **WHEN** bwrap reports version `0.12.0`
- **THEN** CheckBwrapVersion returns a non-empty warning and nil error

#### Scenario: Older version — ERROR
- **WHEN** bwrap reports version `0.10.0`
- **THEN** CheckBwrapVersion returns a non-nil error

#### Scenario: Major version bump — ERROR
- **WHEN** bwrap reports version `1.0.0`
- **THEN** CheckBwrapVersion returns a non-nil error

#### Scenario: Version output unparseable — ERROR
- **WHEN** `bwrap --version` produces output with no recognisable version number
- **THEN** CheckBwrapVersion returns a non-nil error

### Requirement: strace version check

CheckStraceVersion SHALL run `strace --version`, parse the version string, and classify it against the pinned version 6.18.

- OK tier (`6.18`): return `("", nil)`.
- WARN tier (`6.19` through `6.x`): return `(warning, nil)`.
- ERROR tier (`< 6.18` or `>= 7.0`): return `("", error)`.

#### Scenario: Exact pinned version — OK
- **WHEN** strace reports version `6.18`
- **THEN** CheckStraceVersion returns `("", nil)`

#### Scenario: Higher minor, same major 6 — WARN
- **WHEN** strace reports version `6.19`
- **THEN** CheckStraceVersion returns a non-empty warning and nil error

#### Scenario: Older version — ERROR
- **WHEN** strace reports version `6.17`
- **THEN** CheckStraceVersion returns a non-nil error

#### Scenario: Major version bump — ERROR
- **WHEN** strace reports version `7.0`
- **THEN** CheckStraceVersion returns a non-nil error

#### Scenario: Version output unparseable — ERROR
- **WHEN** `strace --version` produces output with no recognisable version number
- **THEN** CheckStraceVersion returns a non-nil error

### Requirement: bwrap version compatibility enforcement

Sandbox.Run SHALL call CheckBwrapVersion after resolving the bwrap binary and SHALL enforce the result before executing any sandboxed command. A WARN result SHALL cause a warning message to be printed to stderr; execution SHALL continue. An ERROR result SHALL propagate as an error, preventing execution.

#### Scenario: Compatible bwrap version — execution proceeds
- **WHEN** bwrap is installed at a compatible version (OK or WARN tier)
- **THEN** Sandbox.Run proceeds to execute the sandboxed command

#### Scenario: Incompatible bwrap version — execution blocked
- **WHEN** bwrap is installed at an incompatible version (ERROR tier)
- **THEN** Sandbox.Run returns an error without executing the command
