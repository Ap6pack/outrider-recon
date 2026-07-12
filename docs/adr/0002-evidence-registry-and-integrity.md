# ADR 0002: Evidence registry and integrity verification

## Status

Accepted.

## Context

Outrider run folders already separate stable run identity (`manifest.json`) from append-only workflow state (`run.jsonl`). Operators also need deterministic offline registration of local evidence artifacts so later review can detect missing, modified, malformed, or unsafe artifact paths without adding recon execution, approval semantics, network behavior, a database, or a web interface.

## Decision

Outrider uses a dedicated append-only `evidence.jsonl` registry in each run folder. Each line is one `evidence_registered` JSON object with schema version 1, an independent evidence sequence, UUID4 evidence ID, manifest run ID, UTC registration timestamp, actor, relative artifact path, artifact type, SHA-256 hash, size, and optional provenance notes.

Artifact contents live under `artifacts/`. The registry stores only metadata, provenance, paths, sizes, and hashes. It does not store artifact contents.

`evidence.jsonl` is intentionally separate from:

- `manifest.json`, which remains stable run identity metadata and is not rewritten during evidence registration;
- `run.jsonl`, which remains the append-only workflow-state authority and does not receive evidence records.

Evidence hashing uses Python standard-library streaming SHA-256 over bounded binary chunks. The implementation derives `size_bytes` from the bytes hashed and checks file metadata before and after hashing to detect changes when reasonably possible.

Evidence paths must be canonical relative POSIX paths beneath `artifacts/`. Absolute paths, traversal, control files, directories, symlinks, symlinked parent directories, and non-regular files are rejected. Registration and verification do not follow symlinks.

A registered path may appear only once. Updated or replaced artifacts require a new artifact filename and a new registry entry.

Verification re-hashes selected artifacts, compares both SHA-256 and size, and reports `verified`, `missing`, `mismatch`, or `unsafe`. Verification is read-only and available for archived runs.

Evidence registration requires a valid manifest and a valid workflow state stream. It is allowed in any valid state except `archived`; archived runs reject new evidence registration.

## Consequences and limitations

- Evidence registration is append-only in normal operation and flushes/fsyncs appended records for durability.
- There is no filesystem immutability guarantee; operators and host controls remain responsible for protecting artifact files.
- There is no concurrent-writer guarantee in this decision.
- Evidence registration does not grant authorization, infer approval, or validate whether collecting an artifact was authorized.
- Evidence registration does not perform finding validation and does not classify findings.
- Evidence registration and verification perform no network activity.
