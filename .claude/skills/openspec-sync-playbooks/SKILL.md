---
name: openspec-sync-playbooks
description: Sync delta playbooks from a change to main playbooks. Use when the user wants to update main playbooks with changes from a delta, without archiving the change.
license: MIT
compatibility: Requires openspec CLI.
metadata:
  author: nonpop
  version: "1.0"
---

Sync delta playbooks from a change to main playbooks.

This is an **agent-driven** operation - you will read delta playbook files and directly edit main playbook files to apply the changes. This allows intelligent merging (e.g., adding a use case without copying the entire playbook).

**Input**: Optionally specify a change name. If omitted, check if it can be inferred from conversation context. If vague or ambiguous you MUST prompt for available changes.

**Steps**

1. **If no change name provided, prompt for selection**

   Run `openspec list --json` to get available changes. Use the **AskUserQuestion tool** to let the user select.

   Show changes that have delta playbooks (under `playbooks/` directory).

   **IMPORTANT**: Do NOT guess or auto-select a change. Always let the user choose.

2. **Find delta playbooks**

   Look for delta playbook files in `openspec/changes/<name>/playbooks/*/playbook.md`.

   Each delta playbook file contains sections like:
   - `## ADDED Use Cases` - New use cases to add
   - `## MODIFIED Use Cases` - Changes to existing use cases
   - `## REMOVED Use Cases` - Use cases to remove

   If no delta playbooks found, inform user and stop.

3. **For each delta playbook, apply changes to main playbooks**

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

4. **Show summary**

   After applying all changes, summarize:
   - Which playbooks were updated
   - What changes were made (use cases added/modified/removed)

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
```

**Key Principle: Intelligent Merging**

Unlike programmatic merging, you can apply **partial updates**:
- To modify a single step, just include that use case under MODIFIED - don't copy unrelated use cases
- The delta represents *intent*, not a wholesale replacement
- Use your judgment to merge changes sensibly

**Output On Success**

```
## Playbooks Synced: <change-name>

Updated main playbooks:

**<goal-1>**:
- Added use case: "Run command in sandbox"
- Modified use case: "Network isolation" (updated THEN step)

**<goal-2>**:
- Created new playbook
- Added use case: "Restrict file access"

Main playbooks are now updated. The change remains active - archive when implementation is complete.
```

**Guardrails**
- Read both delta and main playbooks before making changes
- Preserve existing content not mentioned in delta
- If something is unclear, ask for clarification
- Show what you're changing as you go
- The operation should be idempotent - running twice should give same result
