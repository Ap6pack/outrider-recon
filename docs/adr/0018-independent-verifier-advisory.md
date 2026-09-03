# ADR 0018: Independent verifier is advisory

## Context

A `finding_candidate` claim in a skill result is a producer's assertion. Outrider already re-checks a candidate's *provenance* during promotion and via `finding verify` (source-result presence, source SHA-256, source-claim snapshot, evidence integrity, current scope). It does not attempt to *refute* the claim. Tools in this space (for example VulnHunter's verify phase) gain confidence by having a second, independent agent try to falsify a finding before a human reviews it. Outrider adds that step, but it must not become a gate that silently promotes or discards candidates.

## Decision

Outrider adds an independent verifier that produces advisory verdicts over finding candidates. It never promotes and never deletes.

- The verifier iterates the candidates surfaced by `list_finding_candidates`. For each candidate it independently re-derives evidence status (`verify_all_evidence`) and current scope (`evaluate_scope_path`), and attempts to falsify the candidate's statement against its cited evidence.
- Each verdict is one of `supported`, `refuted`, or `insufficient_evidence`, with a rationale, and is written to `contracts/verification/` under a versioned `verification-v1` contract. Verdicts are append artifacts; they do not modify `findings.jsonl`, `run.jsonl`, `evidence.jsonl`, `approvals.jsonl`, scope, or state.
- A verdict is informational to the human reviewer. It does not change `promotion_eligible` in the finding-candidate projection, and it does not by itself allow or block promotion. A human may promote a `refuted` candidate or decline a `supported` one; the reviewer remains the decision-maker (ADR 0006).
- When executed by an agent, the verifier runs in a separate context from the producing agent so the falsification attempt is genuinely independent. A deterministic analyzer variant is used for tests.

## Consequences and limitations

The verifier raises reviewer signal without adding automation authority: it cannot certify, promote, discard, or re-scope. Its verdicts are only as good as the cited evidence and the current scope at verification time; a `supported` verdict is not proof, and a `refuted` verdict is not a veto. Verdicts are point-in-time and are not signed or authenticated. Surfacing an `unverified_candidate_count` in the workflow guide is a convenience for reviewers and does not gate any transition.
