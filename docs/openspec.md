# OpenSpec Reference

Quick reference for understanding OpenSpec specification-driven development.

## What is OpenSpec?

OpenSpec structures software changes through artifacts (planning documents) and delta specifications that show exactly what's changing in a system.

## Artifacts

Documents that guide a change from planning to implementation.

### proposal.md

Captures the intent and scope of the change.

**Sections:**
- **Why** - Problem or motivation
- **What Changes** - High-level summary of modifications
- **Capabilities** - New/Modified/Removed capabilities
- **Impact** - What this affects (dependencies, breaking changes, etc.)

### specs/ (delta specs)

Shows exactly what's changing in requirements, not the full specification.

**Three sections:**

**ADDED** - New requirements being introduced
- On archive: appends to main specs

**MODIFIED** - Updates to existing requirements
- On archive: replaces existing versions in main specs

**REMOVED** - Requirements being deprecated
- On archive: deletes from main specs

**Format:**
```markdown
## ADDED Requirements

### Requirement: Feature name
The system SHALL/MUST/SHOULD/MAY...

#### Scenario: Concrete example
- WHEN condition
- AND another condition
- THEN expected behavior

## MODIFIED Requirements

### Requirement: Updated feature (was: Old name)
The system SHALL...

## REMOVED Requirements

### Requirement: Deprecated feature
(Explanation of why this is being removed)
```

**Requirements use RFC 2119 keywords:**
- MUST/SHALL - Mandatory
- SHOULD - Recommended
- MAY - Optional

### design.md

Technical approach and architectural decisions.

**Sections:**
- **Context** - Background, constraints, existing system state
- **Goals / Non-Goals** - What this design achieves and explicitly doesn't
- **Decisions** - Key technical choices with rationale and alternatives considered
- **Risks / Trade-offs** - Known limitations and their mitigations

### tasks.md

Implementation checklist with concrete, actionable tasks.

**Format:**
```markdown
## 1. Category

- [ ] 1.1 Specific task description
- [ ] 1.2 Another task
- [x] 1.3 Completed task

## 2. Next Category

- [ ] 2.1 Task description
```

## Configuration

**config.yaml** provides context for artifact generation:

```yaml
schema: spec-driven

context: |
  Tech stack: ...
  Domain knowledge: ...
  Coding conventions: ...

rules:
  proposal:
    - Project-specific guidance for proposals
  specs:
    - Project-specific guidance for specs
  design:
    - Project-specific guidance for design
  tasks:
    - Project-specific guidance for tasks
```

**Context** is injected into all artifact generation. **Rules** apply to specific artifact types.

## Key Concepts

**specs/** - Source of truth documenting current system behavior. Organized by domain/feature. Persists across changes.

**changes/** - Isolated folders containing artifacts and delta specs for proposed modifications. Enables parallel work. Archived after completion.

**Delta specs** - Show only what's changing (ADDED/MODIFIED/REMOVED), not full specifications. Makes changes clear and enables parallel development.

**Iterative** - Update artifacts as you learn during implementation. Re-verify before archiving.
