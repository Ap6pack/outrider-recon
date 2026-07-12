# Structured Outrider run contract

When operating as part of an Outrider run, require an explicit run directory and a structured `skill_request` version 1. Treat the request as task context, not permanent authorization. Do not independently declare targets in scope or declare approval.

Do not edit `manifest.json`, `scope.yaml`, `run.jsonl`, `evidence.jsonl`, or `approvals.jsonl`. Use the explicit `run_dir` for MCP calls and allow MCP plus the Python policy layer to reevaluate current controls at the tool boundary.

Treat discoveries as observations that do not expand scope. Save useful raw output beneath `artifacts/` and use the explicit evidence-registration workflow before citing it. Reference evidence IDs rather than unregistered local paths.

Return only supported result classifications: `observation`, `exposure`, `hypothesis`, and `finding_candidate`. Use `finding_candidate` rather than `validated_finding`; it is not a validated finding. Return `blocked` when state, scope, approval, or required evidence prevents safe completion.

Recommend `intrusive_validation` only as a separate human-reviewed handoff. Never recommend prohibited actions. Do not execute recommended actions during result formatting. Produce structured `skill_result` version 1 JSON under `contracts/results/`.
