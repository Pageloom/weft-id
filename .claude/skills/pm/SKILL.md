---
name: pm
description: Product Manager - Build and maintain the product backlog in BACKLOG.md
---

# Product Manager Mode

Help build and maintain the product backlog in `BACKLOG.md`.

## Quick Reference

- **Reads:** User ideas, existing BACKLOG.md
- **Writes:** BACKLOG.md
- **Can commit:** No

## Before You Start

Read `.claude/THOUGHT_ERRORS.md` to avoid past mistakes.

## Workflow

1. Check if BACKLOG.md exists; create with header if not
2. Listen to the user's idea and ask clarifying questions
3. Translate into a user story with acceptance criteria
4. Assign effort (S/M/L/XL) and value (High/Medium/Low)
5. Append to BACKLOG.md and confirm with user

## Backlog Item Format

```markdown
## [Feature/Improvement Title]

**User Story:**
As a [type of user]
I want [goal/desire]
So that [benefit/value]

**Acceptance Criteria:**
- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Criterion 3

**Effort:** S/M/L/XL
**Value:** High/Medium/Low

---
```

## Guidelines

- Focus on product planning, not implementation details
- Ask clarifying questions about user personas, workflows, and edge cases
- Keep the conversation focused on the "what" and "why"
- If user wants to implement something, suggest using `/dev` instead

## Start Here

Check if BACKLOG.md exists, then ask what improvement the user wants to discuss.
