# ADR 0017: Governed orchestrator loop

## Context

Outrider already defines a skill interchange (`skill_request`/`skill_result` v1) and a deterministic control plane (scope, approval, workflow state, evidence, finding promotion). Until now the only automation over that interchange was advisory: `workflow_guide.build_workflow_guide()` computes a recommended next action but performs nothing. Driving a run still required a human to read the guide and issue each request by hand. An agent-to-agent loop that advances a run automatically is useful, but only if it cannot widen authorization, skip evidence discipline, or promote findings on its own.

## Decision

Outrider adds a Python orchestrator that drives a run through repeated request/result hops while re-evaluating every control on each hop. The orchestrator is a convenience driver over existing validated primitives; it introduces no new authority.

- Each hop is created only through `create_skill_request`, which refuses when current scope, approval, evidence, or workflow state disallow the request. The orchestrator never writes contract files, evidence, approvals, or state events directly.
- Skill execution is performed by an injected `Executor`; the orchestrator does not itself run skills or make network calls. Deterministic tests inject a stub executor; live execution injects an out-of-process agent executor.
- Results are consumed only after `validate_skill_result` returns `valid`. Next-hop candidates are derived only from validated `discovered_candidates` and `recommended_actions`.
- The orchestrator auto-dispatches only `local_analysis` and `public_source_lookup`. `target_read_only_request` and `target_enumeration` require both a currently active approval grant and an allowed workflow state, checked per hop. `intrusive_validation` and prohibited actions are handoff-only and are never auto-dispatched.
- The loop is bounded (maximum hops, maximum requests, wall-clock, and per-action-class caps) and terminates on quiescence, a bound, or a `blocked` result. It is resumable over the existing `contracts/requests` and `contracts/results` inventory and refuses to proceed when `contract_revision` or `state_revision` indicate concurrent change.
- The orchestrator never creates a `validated_finding`. Promotion remains the human `outrider finding promote` workflow (ADR 0006).

## Consequences and limitations

The orchestrator makes runs advanceable without hand-issuing each request while keeping every existing interlock authoritative. It is not authenticated actor proof, not a concurrency guarantee beyond optimistic revision tokens, and not a finding authority. Live autonomous execution depends on an external agent runtime and its provider safeguards; that mode is disabled by default and documented separately. Because auto-dispatch is capped at local and passive actions, active reconnaissance still requires an explicit standing approval, and intrusive or prohibited actions always require a separate human-reviewed handoff.
