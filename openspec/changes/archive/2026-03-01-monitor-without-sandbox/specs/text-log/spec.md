## MODIFIED Requirements

### Requirement: Text log entry format

MODIFIED: RESULT SHALL be left-padded to 10 characters (longest: `UNENFORCED`).

#### Scenario: Unenforced entry formatted

- **WHEN** Writer receives entry (READ, `/home/user/.ssh/id_rsa`, UNENFORCED, `no-matching-rule`)
- **THEN** the output line is `UNENFORCED READ   /home/user/.ssh/id_rsa  (no-matching-rule)`

### Requirement: Denied-only default filter

MODIFIED: `UNENFORCED` entries SHALL always be included in the output regardless of the `showAllowed` flag. The `showAllowed` flag controls only `OK` entries.

#### Scenario: UNENFORCED entries shown even when showAllowed is false

- **WHEN** Writer is created with showAllowed=false
- **AND** Logger contains entries with results OK, DENY, UNKNOWN, and UNENFORCED
- **THEN** output contains DENY, UNKNOWN, and UNENFORCED entries
- **AND** output does not contain OK entries
