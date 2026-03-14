## ADDED Requirements

### Requirement: Config file composition via extends

The config file format SHALL support an optional top-level `extends` array of strings. Each string SHALL reference another config file to compose into the current config.

`extends` path resolution SHALL follow filesystem rule path semantics:
- absolute paths MUST be used as-is
- relative paths MUST be resolved against the directory of the file that declares the `extends` entry
- `~` prefixes MUST expand to the current user's home directory

The loader SHALL resolve `extends` recursively and MUST reject cyclic references.

#### Scenario: Root config composes rules from parent config
- **WHEN** `Load` is called on a config file that contains `extends = ["/path/base.toml"]` and both files are valid
- **THEN** the returned `Config` contains rules from both files

#### Scenario: Relative extends path resolves against declaring file directory
- **WHEN** `Load` is called on `/work/project/execave.toml` containing `extends = ["../base.toml"]`
- **THEN** the loader resolves the reference to `/work/base.toml`

#### Scenario: Tilde extends path resolves to user home
- **WHEN** `Load` is called on a config containing `extends = ["~/.config/listree/common.toml"]`
- **THEN** the loader resolves the reference under the current user's home directory

#### Scenario: Cyclic extends chain is rejected
- **WHEN** `Load` is called on a config graph where `a.toml` extends `b.toml` and `b.toml` extends `a.toml`
- **THEN** `Load` returns an error indicating an `extends` cycle

### Requirement: Layered merge and validation model

For layered config composition, validation MUST be performed in two phases:
1. Each loaded file SHALL be validated independently using the same single-file validation rules.
2. The merged rule set SHALL be formed by union of all rules, removing only exact duplicate rules, and then validated again using the same validators as a single config file.

The merged validation result SHALL be order-independent with respect to `extends` entry order.

#### Scenario: Exact duplicate rules across files are accepted
- **WHEN** two composed config files contain the exact same rule string
- **THEN** `Load` succeeds and the merged policy contains one effective copy of that rule

#### Scenario: Contradictory filesystem rules across files are rejected
- **WHEN** composed configs include `fs = ["ro:/foo"]` in one file and `fs = ["rw:/foo"]` in another
- **THEN** `Load` returns a validation error for duplicate/conflicting path policy

#### Scenario: Contradictory network rules across files are rejected
- **WHEN** composed configs include `net = ["http:example.com:443"]` in one file and `net = ["none:example.com:443"]` in another
- **THEN** `Load` returns a validation error for conflicting net rule identity

#### Scenario: Extends order does not change the outcome
- **WHEN** `Load` is called for two root configs that reference the same parent files in different `extends` order
- **THEN** both loads produce equivalent success/failure outcomes under merged validation

### Requirement: Source-aware layered validation errors

For validation failures detected after layered merge, error messages SHALL identify the conflicting rules and the source config file path for each conflicting rule.

#### Scenario: Cross-file fs conflict includes both source files
- **WHEN** layered merge detects a filesystem conflict between rules from `/path/base.toml` and `/path/execave.toml`
- **THEN** the returned error includes both file paths and both conflicting rule strings

#### Scenario: Cross-file net conflict includes both source files
- **WHEN** layered merge detects a net identity conflict between rules from two different files
- **THEN** the returned error includes both file paths and both conflicting rule strings

### Requirement: All loaded config files are protected from explicit writability

Explicit writable filesystem rules targeting any loaded config file (root or extended parent) SHALL be rejected during validation.

#### Scenario: Parent config path explicitly writable is rejected
- **WHEN** a layered config set includes a rule that grants `rw` access to an extended parent config file path
- **THEN** `Load` returns an error indicating the config file must not be writable

#### Scenario: Root config path explicitly writable is rejected in layered mode
- **WHEN** a layered config set includes a rule that grants `rw` access to the root config file path
- **THEN** `Load` returns an error indicating the config file must not be writable
