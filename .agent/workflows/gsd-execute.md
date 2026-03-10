---
description: Execute GSD plans for a phase.
---

1.  **Inventory Plans**: List all `PLAN.md` files for the specified phase.
2.  **Analyze Dependencies**: Group plans into sequential waves based on `depends_on` and file ownership.
3.  **Wave Execution**:
    - For each wave: Execute independent plans in parallel.
    - Each execution gets a fresh context and loads the full `PLAN.md` as its primary prompt.
4.  **Atomic Commits**: Each completed task must be committed immediately with `feat(...)` or `fix(...)` prefix.
5.  **Verify Wave**: Confirm that the wave's deliverables meet the specified criteria.
6.  **Summarize**: Generate `<phase_num>-<plan_num>-SUMMARY.md` for each completed plan.
7.  **Transition**: Once all waves are complete, run `/gsd:verify-work` (manual UAT).
