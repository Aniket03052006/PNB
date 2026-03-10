---
description: Plan a specific phase of the GSD roadmap.
---

1.  **Select Phase**: Identify the target phase from `ROADMAP.md`.
2.  **Discuss Phase**:
    - Analyze the phase for gray areas (UI density, API behavior, error handling).
    - Capture user implementation decisions in `<phase_num>-CONTEXT.md`.
3.  **Research (Optional)**: Perform "Level 2" research if new libraries or APIs are introduced.
4.  **Plan Generation**:
    - Spawn a specialized planner to decompose the phase into 2-3 atomic tasks per plan.
    - Generate `<phase_num>-<plan_num>-PLAN.md` files with XML meta-prompts.
    - Ensure every roadmap requirement for the phase is mapped to a plan.
5.  **Validation**: Verify plans against the roadmap goals and goal-backward criteria.
6.  **Commit**: Commit the `.planning/` changes with a descriptive message.
