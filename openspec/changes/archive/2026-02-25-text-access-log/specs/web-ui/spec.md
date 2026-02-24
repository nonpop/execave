## MODIFIED Requirements

### Requirement: Denied-only filter

The web UI SHALL display only DENY and UNKNOWN entries by default. A "Denied only" checkbox SHALL control this filter. The initial checked state SHALL be determined by server-side configuration: checked when `FilterDefaults.ShowAllowed` is false (default), unchecked when true. When unchecked, OK entries are also displayed. The filter SHALL apply to both the initial page render and dynamically streamed SSE entries.

#### Scenario: Default view hides OK entries

- **WHEN** Logger contains entries with results OK, DENY, and UNKNOWN
- **AND** FilterDefaults.ShowAllowed is false
- **AND** GET / is requested
- **THEN** only DENY and UNKNOWN entries are visible in the rendered page
- **AND** the "Denied only" checkbox is checked

#### Scenario: ShowAllowed unchecks denied-only checkbox

- **WHEN** FilterDefaults.ShowAllowed is true
- **AND** GET / is requested
- **THEN** OK entries are visible in the rendered page
- **AND** the "Denied only" checkbox is unchecked

#### Scenario: Unchecking denied-only reveals OK entries

- **WHEN** the client unchecks the "Denied only" checkbox
- **THEN** OK entries become visible without page reload

#### Scenario: Re-checking denied-only hides OK entries

- **WHEN** the client re-checks the "Denied only" checkbox
- **THEN** OK entries are hidden again without page reload

### Requirement: Nolog filter

The web UI SHALL apply log rule resolution to determine entry visibility. A "Apply nolog rules" checkbox SHALL control this filter. The initial checked state SHALL be determined by server-side configuration: checked when `FilterDefaults.ShowNolog` is false (default), unchecked when true. When checked, entries whose target matches a `nolog` rule (and is not overridden by a more specific `log` rule) are hidden. When unchecked, all entries are shown regardless of log rules. The filter SHALL apply to both the initial page render and dynamically streamed SSE entries.

#### Scenario: Nolog rule hides matching entries

- **WHEN** config contains `fs:nolog:/home/user/project`
- **AND** FilterDefaults.ShowNolog is false
- **AND** Logger contains a DENY entry for `/home/user/project/cache/data`
- **AND** GET / is requested with "Apply nolog rules" checked
- **THEN** the entry is not visible
- **AND** the "Apply nolog rules" checkbox is checked

#### Scenario: ShowNolog unchecks apply-nolog checkbox

- **WHEN** FilterDefaults.ShowNolog is true
- **AND** GET / is requested
- **THEN** nolog-suppressed entries are visible in the rendered page
- **AND** the "Apply nolog rules" checkbox is unchecked

#### Scenario: Unchecking nolog filter reveals suppressed entries

- **WHEN** config contains `fs:nolog:/home/user/project`
- **AND** Logger contains entries for paths under `/home/user/project`
- **AND** the client unchecks the "Apply nolog rules" checkbox
- **THEN** suppressed entries become visible without page reload

#### Scenario: Log rule override makes entry visible despite nolog

- **WHEN** config contains `fs:nolog:/home/user/project` and `fs:log:/home/user/project/secret`
- **AND** Logger contains a DENY entry for `/home/user/project/secret/key.pem`
- **AND** GET / is requested with "Apply nolog rules" checked
- **THEN** the entry is visible (log rule overrides nolog)

### Requirement: Filter checkboxes displayed

GET / SHALL include a "Denied only" checkbox and an "Apply nolog rules" checkbox. The initial checked state of each checkbox SHALL be determined by the server's `FilterDefaults` configuration, not hardcoded.

#### Scenario: Default filter state (no flags)

- **WHEN** FilterDefaults has ShowAllowed=false and ShowNolog=false
- **AND** GET / is requested
- **THEN** the "Denied only" checkbox is checked
- **AND** the "Apply nolog rules" checkbox is checked

#### Scenario: Both filters overridden

- **WHEN** FilterDefaults has ShowAllowed=true and ShowNolog=true
- **AND** GET / is requested
- **THEN** the "Denied only" checkbox is unchecked
- **AND** the "Apply nolog rules" checkbox is unchecked
