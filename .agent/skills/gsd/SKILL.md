# GSD Skill: Get Shit Done

> A light-weight and powerful meta-prompting, context engineering, and spec-driven development system.

## 📋 Overview
GSD provides a structured, phase-driven workflow for building complex features with high reliability and zero context rot.

**Phases:**
1. **Discuss**: Capture implementation decisions before planning.
2. **Plan**: Decompose phases into atomic, parallel-optimized plans.
3. **Execute**: Run plans in waves with fresh context per plan.
4. **Verify**: Human-in-the-loop verification of deliverables.

## 🛠️ Instructions

### 1. Goal-Backward Planning
When planning, start from the desired outcome and work backwards to derive required truths, artifacts, and wiring. Use the `ROADMAP.md` as the source of truth for scope.

### 2. Atomic Task Breakdown
- **Tasks per Plan**: 2-3 maximum.
- **Complexity**: Tasks should take 15-60 mins for Claude to implement.
- **Specificity**: Every task must have exact `<files>`, detailed `<action>`, `<verify>` command, and measurable `<done>` criteria.

### 3. XML Meta-Prompting
Always structure implementation plans using XML tags to provide clear boundaries for Claude executors.

```xml
<task type="auto">
  <name>Task Name</name>
  <files>path/to/file</files>
  <action>Instructions...</action>
  <verify>npm test</verify>
  <done>Criteria met</done>
</task>
```

### 4. Context Engineering
Maintain project state in the following files:
- `PROJECT.md`: High-level vision.
- `ROADMAP.md`: Phase-level breakdown.
- `REQUIREMENTS.md`: Detailed feature requirements.
- `STATE.md`: Memory across sessions.

## 🔗 References
- Templates: `.agent/skills/gsd/references/*.md`
- Subagent Prompts: `.agent/skills/gsd/references/*-subagent-prompt.md`

## 🏁 Verification
Every phase execution must be verified against the `ROADMAP.md` goals using the `verify-work` protocol.
