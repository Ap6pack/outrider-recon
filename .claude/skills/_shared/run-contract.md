# Structured Outrider run contract

When operating as part of an Outrider run, require an explicit run directory and a structured `skill_request` version 1. Treat the request as task context, not permanent authorization. Do not independently declare targets in scope or declare approval.

Do not edit `manifest.json`, `scope.yaml`, `run.jsonl`, `evidence.jsonl`, or `approvals.jsonl`. Use the explicit `run_dir` for MCP calls and allow MCP plus the Python policy layer to reevaluate current controls at the tool boundary.

Treat discoveries as observations that do not expand scope. Save useful raw output beneath `artifacts/` and use the explicit evidence-registration workflow before citing it. Reference evidence IDs rather than unregistered local paths.

Return only supported result classifications: `observation`, `exposure`, `hypothesis`, and `finding_candidate`. Use `finding_candidate` rather than `validated_finding`; it is not a validated finding. Return `blocked` when state, scope, approval, or required evidence prevents safe completion.

Recommend `intrusive_validation` only as a separate human-reviewed handoff. Never recommend prohibited actions. Do not execute recommended actions during result formatting. Produce structured `skill_result` version 1 JSON under `contracts/results/`.

## Finding promotion boundary

Skills may classify supported claims as `observation`, `exposure`, `hypothesis`, or `finding_candidate` only. Skills must never emit `validated_finding`, `confirmed_vulnerability`, `exploited`, or `compromised`; only the Python `outrider finding promote` workflow may create a `validated_finding` after human review, registered evidence verification, current deterministic scope validation, and permitted workflow state checks.

Recommendations in a skill result are handoff suggestions, not findings. Claim confidence and `suggested_severity` remain advisory; the human reviewer must explicitly choose final promoted-finding severity and confidence. `findings.jsonl` is append-only and is the deterministic source for promoted findings. Skills must not modify `findings.jsonl` or `findings.md`. No skill may claim exploitation or compromise without a separate authorized workflow outside this feature.
