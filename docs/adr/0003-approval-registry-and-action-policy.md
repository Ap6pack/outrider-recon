# ADR 0003: Approval registry and action policy

## Status

Accepted.

## Context

Outrider needs deterministic, offline decisions about whether a proposed operator action is allowed, denied, or invalid. The decision must combine stable run identity, workflow state, current scope, and explicit human approvals without executing recon activity or sending traffic.

## Decision

Approvals are stored in a dedicated append-only `approvals.jsonl` registry. The registry is separate from `manifest.json`, which remains stable run identity; `run.jsonl`, which remains the workflow-state authority; and `evidence.jsonl`, which remains artifact-integrity metadata.

The approval stream uses schema version 1 and independent sequence numbers. It supports append-only `approval_granted` and `approval_revoked` events. Grant events record a UUID approval ID, UUID event ID, run ID, timestamp, operator-provided actor string, action type, normalized exact candidate, candidate type, expiration time, reason, and optional conditions. Revocation events reference an existing active approval ID and append actor, timestamp, and reason without editing the grant.

Approvals are exact-candidate and action-specific. Domain comparison is normalized and case-insensitive, URL candidates store only the hostname, and IP candidates use deterministic `ipaddress` normalization. Wildcard approval candidates are not supported. Expiration is required and bounded to no more than seven days.

Action policy evaluation is a decision only. It validates manifest, workflow state, scope, registry, action type, and candidate; permanently denies prohibited categories; applies workflow-state restrictions; applies scope; then checks whether an active exact matching approval is required and present.

Scope takes precedence over approval. A current scope-file change can invalidate an earlier approval during action evaluation. Workflow state can deny an otherwise approved action. Prohibited action categories cannot be approved and remain denied even if a registry is manually altered to contain a matching grant.

The `actor` field is attribution metadata supplied by the operator. It is not authenticated identity, a digital signature, proof of written client authorization, a substitute for the manifest authorization reference, or a substitute for rules of engagement.

## Consequences and limitations

- Approval history is append-only and auditable within a single local run folder.
- Existing runs without `approvals.jsonl` remain usable and are treated as having zero approvals.
- The action checker performs no action and makes no network request.
- There is no authenticated approver identity and no digital signature.
- There is no concurrent-writer guarantee for simultaneous registry appends.
- There is no action execution, MCP enforcement, Claude skill-contract enforcement, or web-control-plane enforcement yet.
