# ADR 0016: Guided engagement workflow

## Status

Accepted.

## Context

The web portal is the normal human entry point, but beginners need plain-language progress and next actions without learning internal state names or registry files.

## Decision

Outrider projects a deterministic guide from existing run state, scope, evidence, contract, and finding data. The guide is not persisted and is not a new source of truth. It uses fixed beginner-facing phase labels, a seven-step progress journey, one recommended next action, and explicit human transitions guarded by a guide revision.

Guided actions only append existing state-transition events. They do not run discovery, invoke MCP automatically, capture evidence, execute skills or Claude, promote findings, generate reports, export data, or notify anyone.

Basic mode explains progress and safe next steps. Advanced Workspace remains available for existing technical controls, including scope, state, evidence, approvals, contracts, findings, enrichment, and integrity review. Hidden static test markers are not used.

## Consequences

The loopback portal remains unauthenticated and single-operator. Guidance has stale-review protection, but it is still local workflow assistance rather than authentication or multi-user coordination.
