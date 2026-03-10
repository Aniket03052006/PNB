---
description: Initialize a new GSD project or milestone.
---

1.  **Analyze Request**: Determine if this is a brand new project or a new milestone for an existing codebase.
2.  **Context Discovery**:
    - If existing code: Run `/gsd:map-codebase` logic (internal exploration) to understand the stack, architecture, and conventions.
    - If new project: Ask Socratic questions to define goals, tech preferences, and constraints.
3.  **Research (Optional)**: If the domain is niche or complex, perform targeted research to identify best practices and pitfalls.
4.  **Requirement Extraction**: Generate `.planning/REQUIREMENTS.md` with scoped MUST-HAVES and deferred ideas.
5.  **Roadmap Creation**: Generate `.planning/ROADMAP.md` mapping requirements to numbered phases.
6.  **State Initialization**: Generate `.planning/STATE.md` to track progress and `.planning/PROJECT.md` for high-level context.
7.  **Final Review**: Present the roadmap to the user for approval.
