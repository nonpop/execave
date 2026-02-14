---
name: "OPSX: Sync"
description: Sync delta specs and playbooks from a change to main
category: Workflow
tags: [workflow, specs, playbooks, experimental]
---

Sync delta specs and playbooks from a change to main.

This is an **agent-driven** operation - you will read delta files and directly edit main files to apply the changes. This allows intelligent merging (e.g., adding a scenario without copying the entire requirement, or adding a use case without copying the entire playbook).

**Input**: Optionally specify a change name after `/opsx:sync` (e.g., `/opsx:sync add-auth`). If omitted, check if it can be inferred from conversation context. If vague or ambiguous you MUST prompt for available changes.

**Steps**

1. **If no change name provided, prompt for selection**

   Run `openspec list --json` to get available changes. Use the **AskUserQuestion tool** to let the user select.

   Show changes that have delta specs (under `specs/` directory) or delta playbooks (under `playbooks/` directory).

   **IMPORTANT**: Do NOT guess or auto-select a change. Always let the user choose.

2. **Find delta specs**

   Look for delta spec files in `openspec/changes/<name>/specs/*/spec.md`.

   Each delta spec file contains sections like:
   - `## ADDED Requirements` - New requirements to add
   - `## MODIFIED Requirements` - Changes to existing requirements
   - `## REMOVED Requirements` - Requirements to remove
   - `## RENAMED Requirements` - Requirements to rename (FROM:/TO: format)

3. **Find delta playbooks**

   Look for delta playbook files in `openspec/changes/<name>/playbooks/*/playbook.md`.

   Each delta playbook file contains sections like:
   - `## ADDED Use Cases` - New use cases to add
   - `## MODIFIED Use Cases` - Changes to existing use cases
   - `## REMOVED Use Cases` - Use cases to remove
   - `## RENAMED Use Cases` - Use cases to rename (FROM:/TO: format)

   If no delta specs and no delta playbooks found, inform user and stop.

4. **For each delta spec, apply changes to main specs**

   For each capability with a delta spec at `openspec/changes/<name>/specs/<capability>/spec.md`:

   a. **Read the delta spec** to understand the intended changes

   b. **Read the main spec** at `openspec/specs/<capability>/spec.md` (may not exist yet)

   c. **Apply changes intelligently**:

      **ADDED Requirements:**
      - If requirement doesn't exist in main spec → add it
      - If requirement already exists → update it to match (treat as implicit MODIFIED)

      **MODIFIED Requirements:**
      - Find the requirement in main spec
      - Apply the changes - this can be:
        - Adding new scenarios (don't need to copy existing ones)
        - Modifying existing scenarios
        - Changing the requirement description
      - Preserve scenarios/content not mentioned in the delta

      **REMOVED Requirements:**
      - Remove the entire requirement block from main spec

      **RENAMED Requirements:**
      - Find the FROM requirement, rename to TO

   d. **Create new main spec** if capability doesn't exist yet:
      - Create `openspec/specs/<capability>/spec.md`
      - Add Purpose section (can be brief, mark as TBD)
      - Add Requirements section with the ADDED requirements

5. **For each delta playbook, apply changes to main playbooks**

   For each playbook with a delta at `openspec/changes/<name>/playbooks/<goal>/playbook.md`:

   a. **Read the delta file** to understand the intended changes

   b. **Read the main playbook** at `openspec/playbooks/<goal>/playbook.md` (may not exist yet)

   c. **Apply changes intelligently**:

      **ADDED Use Cases:**
      - If use case doesn't exist in main playbook → add it
      - If use case already exists → update it to match (treat as implicit MODIFIED)

      **MODIFIED Use Cases:**
      - Find the use case in main playbook
      - Apply the changes - this can be:
        - Modifying GIVEN/WHEN/THEN steps
        - Changing the use case description
        - Adding or removing steps
      - Preserve content not mentioned in the delta

      **REMOVED Use Cases:**
      - Remove the entire use case block from main playbook

   d. **Create new main playbook** if it doesn't exist yet:
      - Create `openspec/playbooks/<goal>/playbook.md`
      - Add the ADDED use cases

6. **Show summary**

   After applying all changes, summarize:
   - Which capabilities were updated (specs)
   - Which user goals were updated (playbooks)
   - What changes were made (requirements/use cases added/modified/removed/renamed)

**Delta Spec Format Reference**

```markdown
## ADDED Requirements

### Requirement: New Feature
The system SHALL do something new.

#### Scenario: Basic case
- **WHEN** user does X
- **THEN** system does Y

## MODIFIED Requirements

### Requirement: Existing Feature
#### Scenario: New scenario to add
- **WHEN** user does A
- **THEN** system does B

## REMOVED Requirements

### Requirement: Deprecated Feature

## RENAMED Requirements

- FROM: `### Requirement: Old Name`
- TO: `### Requirement: New Name`
```

**Delta Playbook Format Reference**

```markdown
## ADDED Use Cases

### Use Case: Run command in sandbox
The user runs a command with filesystem isolation.

- **GIVEN** a config with filesystem rules restricting /home to read-only
- **WHEN** the user runs `execave -- touch /home/test`
- **THEN** the command fails with a permission error

## MODIFIED Use Cases

### Use Case: Run command in sandbox
- **GIVEN** a config with filesystem rules restricting /home to read-only
- **WHEN** the user runs `execave -- touch /home/test`
- **THEN** the command fails with exit code 1 and stderr contains "Permission denied"

## REMOVED Use Cases

### Use Case: Legacy sandbox mode
**Reason**: Replaced by new sandbox configuration
**Migration**: Use filesystem rules instead

## RENAMED Use Cases

- FROM: `### Use Case: Old Name`
- TO: `### Use Case: New Name`
```

**Key Principle: Intelligent Merging**

Unlike programmatic merging, you can apply **partial updates**:
- To add a scenario, just include that scenario under MODIFIED - don't copy existing scenarios
- To modify a single step, just include that use case under MODIFIED - don't copy unrelated use cases
- The delta represents *intent*, not a wholesale replacement
- Use your judgment to merge changes sensibly

**Output On Success**

```
## Synced: <change-name>

Updated main specs:

**<capability-1>**:
- Added requirement: "New Feature"
- Modified requirement: "Existing Feature" (added 1 scenario)

**<capability-2>**:
- Created new spec file
- Added requirement: "Another Feature"

Updated main playbooks:

**<goal-1>**:
- Added use case: "Run command in sandbox"
- Modified use case: "Network isolation" (updated THEN step)

**<goal-2>**:
- Created new playbook
- Added use case: "Restrict file access"

Main specs and playbooks are now updated. The change remains active - archive when implementation is complete.
```

**Guardrails**
- Read both delta and main files before making changes
- Preserve existing content not mentioned in delta
- If something is unclear, ask for clarification
- Show what you're changing as you go
- The operation should be idempotent - running twice should give same result
