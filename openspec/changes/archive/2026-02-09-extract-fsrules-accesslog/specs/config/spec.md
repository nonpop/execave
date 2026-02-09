## REMOVED Requirements

### Requirement: Rule syntax validation
**Reason**: Moved to `fs-rules` capability. FS rule parsing and validation is now the responsibility of the `fsrules` package. The "Unknown resource type" scenario stays in config under "Config file format" since resource routing remains a config responsibility.
**Migration**: The "Invalid permission type" and "Malformed rule" scenarios are identical in `fs-rules` spec. No behavioral change.

### Requirement: Path normalization
**Reason**: Moved to `fs-rules` capability. Path normalization is FS-specific and co-located with rule parsing.
**Migration**: Requirements and all scenarios are identical in `fs-rules` spec. No behavioral change.

### Requirement: Duplicate paths rejected
**Reason**: Moved to `fs-rules` capability. Cross-rule validation is FS-specific.
**Migration**: Requirements and all scenarios are identical in `fs-rules` spec. No behavioral change.

### Requirement: Config file cannot be explicitly writable
**Reason**: Moved to `fs-rules` capability. This validation depends on FS rule types and permissions.
**Migration**: Requirements and all scenarios are identical in `fs-rules` spec. No behavioral change.

### Requirement: Managed paths cannot be targeted by rules
**Reason**: Moved to `fs-rules` capability. Managed path checking is FS-specific validation.
**Migration**: Requirements and all scenarios are identical in `fs-rules` spec. No behavioral change.

## MODIFIED Requirements

### Requirement: Config file format

The config file SHALL be valid JSON containing a `rules` array. Each rule SHALL be a string. Rules are routed by resource prefix: `fs:` rules are parsed by the FS rules engine. Unknown resource prefixes SHALL cause the application to exit with an error before running the command.

#### Scenario: Valid config
- **WHEN** config file contains `{"rules": ["fs:ro:/usr/bin", "fs:rw:/home/user/project"]}`
- **THEN** sandboxed command runs successfully

#### Scenario: Empty rules array
- **WHEN** config file contains `{"rules": []}`
- **THEN** system runs with default-deny (no paths accessible)

#### Scenario: Unknown resource type
- **WHEN** config contains rule `net:allow:443`
- **THEN** system exits with error indicating unknown resource type (MVP only supports `fs`)
