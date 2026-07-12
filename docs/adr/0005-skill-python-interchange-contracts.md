# ADR 0005: Skill/Python interchange contracts

## Status

Accepted.

## Context

Outrider separates Claude skill guidance from deterministic run controls. Skills are useful for reasoning, methodology, routing, prioritization, and reporting, but prose-only instructions are not sufficient as a durable interchange boundary.

## Decision

Outrider defines versioned `skill_request` and `skill_result` JSON contracts. Requests live under `contracts/requests/`; results live under `contracts/results/`. The Python layer keeps a fixed catalog of shipped skill directory names and rejects unknown skill identifiers.

Request creation and validation reload the run manifest, workflow state, scope configuration, approval registry, and evidence registry. A request is task context, not permanent authorization, and policy is reevaluated on every validation. MCP remains independently policy-gated at the tool boundary.

Results must cite registered evidence IDs. Discovered candidates do not expand scope, and `finding_candidate` is not a validated finding. Recommended actions are decisions or handoffs only; they do not execute, alter state, grant approval, modify scope, register evidence, or promote findings.

## Consequences and limitations

The contracts are not authenticated actor proof, signed records, written authorization, automatic execution, automatic evidence capture, finding promotion, or a concurrency guarantee. The same structured contracts can be reused by a future web or control-plane interface without changing the authority split.
