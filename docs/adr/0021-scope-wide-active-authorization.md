# ADR 0021: Scope-wide active-enumeration authorization

## Context

Outrider's governed orchestrator loop (ADR 0017) already hands off between agents
through the request→result contract and auto-dispatches active enumeration when
`evaluate_action` returns `allow`. But approvals are deliberately **per-candidate**
(`grant_approval(run, action_type, candidate, …)`, candidate must be in scope,
bounded expiry ≤ 7 days). An unattended engagement discovers new in-scope hosts as
it runs, so a per-candidate model forces a human grant for each newly discovered
asset — which defeats the goal of a loop that a human only has to *set up*.

The operator's intent is: after the human defines scope and authorization at setup,
the loop should enumerate any in-scope asset unattended, while findings remain
human-reviewed and intrusive/prohibited actions remain handoff-only.

## Decision

Add a **scope-wide active-enumeration authorization**: a single, explicit grant that
authorizes an active action type against *any in-scope candidate*, rather than one
named candidate.

- **Representation.** It is an ordinary `approval_granted` event with the sentinel
  candidate `"*"` and `candidate_type: "scope"`. It flows through the same
  grant / revoke / expiry / registry machinery, so it appears in `list_approvals`,
  is revocable by id, and expires. Only the two ACTIVE action types
  (`target_read_only_request`, `target_enumeration`) may be authorized scope-wide;
  `intrusive_validation` and prohibited actions cannot.
- **Enforcement.** `evaluate_action` still normalizes the candidate and requires it
  to be `allow` under current scope. When no exact per-candidate approval matches, it
  then honors an active scope-wide grant for the same action type — so a scope-wide
  grant only ever authorizes candidates that scope already permits. Out-of-scope
  candidates are denied exactly as before.
- **Bounds unchanged.** A scope-wide grant obeys the same expiry ceiling (≤ 7 days),
  requires a non-empty actor and reason, is only grantable in `scoped`/`collecting`/
  `analyzing`, and refuses an active duplicate.
- **Setup wiring.** Because run creation must leave a run `initialized`, the grant is
  a post-creation step the operator opts into: transition `initialized → scoped`, then
  record the scope-wide grant for both active action types. The opt-in is explicit and
  carries the same authorization reference the engagement was created with. Passive and
  local actions need no grant and are unaffected.

## Consequences and limitations

A human sets scope and authorization once; the loop can then enumerate in-scope assets
without a per-asset approval. The authorization is honest about what it covers — the
whole scope, explicitly, for a bounded time — and remains fully auditable and revocable
in the append-only registry. The real boundaries are unchanged: scope still gates every
candidate, the grant expires, intrusive/prohibited actions stay handoff-only, and
findings are still promoted only by a human. The trade-off is that a scope-wide grant
removes the per-target human checkpoint for active enumeration; it is therefore opt-in,
never the default, and its blast radius is exactly the engagement's authorized scope for
its bounded lifetime. Revoking it (or letting it expire) returns the loop to
handoff-only for active actions.
