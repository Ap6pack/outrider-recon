# ADR 0001: Run manifest and state log

## Context

Outrider run folders need a durable offline identity and a workflow-state record that can be validated without network access. Existing run folders already use `run.jsonl`, so the design must preserve legacy lines while adding a schema-versioned state stream.

## Decision

New run folders contain two separate durable records:

- `manifest.json` stores stable run metadata: schema version, UUID run ID, target, engagement type, creation time, optional creator, optional opaque authorization reference, and relative filenames for `scope.yaml` and `run.jsonl`.
- `run.jsonl` is the append-only authority for workflow state. Versioned events include sequence numbers, event IDs, run IDs, timestamps, actor attribution, previous state, new state, and optional reasons.

The current workflow state is derived by validating and replaying the versioned event sequence. It is not duplicated as mutable state in `manifest.json`, avoiding two competing state authorities.

## Transition validation

The Python state layer validates UUIDs, timezone-aware timestamps, event ordering, event uniqueness, manifest/run-log consistency, recognized states, and explicit transition rules. Transitions require an actor. Transitions to `cancelled` and backward workflow transitions require a reason. Entering `scoped` from `initialized` validates `scope.yaml` first.

## Legacy bootstrap

Legacy run folders without `manifest.json` are not silently assigned a new identity during normal `outrider init` reruns. Operators must explicitly run `outrider state bootstrap`, which validates `scope.yaml`, writes a new manifest, appends a versioned baseline event, and preserves existing legacy `run.jsonl` lines byte-for-byte.

## Consequences and limitations

This design provides a stable UUID run identity, an append-only state log, deterministic validation, and operator attribution. It does not provide a concurrency guarantee yet; simultaneous writers are outside the current contract. Workflow state does not imply approval, authorization, evidence integrity, MCP enforcement, recon execution, or network behavior.
