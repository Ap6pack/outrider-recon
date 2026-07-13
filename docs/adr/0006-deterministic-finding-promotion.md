# ADR 0006: Deterministic finding promotion

## Context

Skill results can identify observations, exposures, hypotheses, and `finding_candidate` claims. A skill-produced candidate is not finding authority: Claude skills must not self-certify findings or claim exploitation, compromise, authenticated reviewer identity, digital authorization, client acceptance, or destructive validation.

## Decision

Outrider stores human-reviewed promoted findings in an append-only `findings.jsonl` registry. A `validated_finding` can be created only through the Python `outrider finding promote` workflow. Promotion requires human-supplied reviewer attribution and metadata, a valid source skill result and linked request, an exact `finding_candidate` source claim, source-result SHA-256 hashing, source-claim snapshot storage, registered evidence IDs whose artifacts verify locally, current deterministic scope allowance for the affected candidate, and a run state of `analyzing` or `reporting`.

`findings.jsonl` is separate from `manifest.json`, `run.jsonl`, `evidence.jsonl`, approvals, skill contracts, and `findings.md`. `findings.md` remains operator-managed Markdown. Promotion performs no automatic execution, network validation traffic, DNS lookup, approval grant, state transition, evidence creation, or scope change. Severity remains a reviewer decision; source suggested severity is advisory.

## Consequences and limitations

The finding registry provides deterministic provenance and read-only verification of source-result presence, source-result hash, source-claim consistency, evidence-record presence, and artifact integrity. Later scope changes do not erase or rewrite historical findings; verification may report that a historically promoted finding is currently out of scope. This feature does not provide authenticated reviewers, digital signatures, client-acceptance semantics, update/delete lifecycle events, broad semantic duplicate detection, concurrent-writer guarantees, exploitation, or automatic Markdown rendering. The Python interface is reusable by future reporting, export, release, or web review planes.
