# ADR 0002: Evidence registry and integrity verification

## Status

Accepted.

## Context

Outrider run folders need a deterministic offline way to register local artifacts, record integrity metadata, and later verify that those artifacts remain present and unchanged. This must not change stable run identity metadata or workflow-state history, and it must not introduce approval, finding-validation, recon-execution, network, database, or web behavior.

## Decision

Each run folder has a dedicated append-only `evidence.jsonl` registry and an `artifacts/` directory. `evidence.jsonl` is separate from `manifest.json`, which remains stable run identity metadata, and from `run.jsonl`, which remains the append-only workflow-state authority.

Evidence records contain metadata only: schema version, independent evidence sequence, event type, UUID4 evidence ID, run ID, registration timestamp, actor, canonical relative artifact path, artifact type, SHA-256 hash, size, media type, source, and note. Artifact contents are not stored in the registry.

Artifacts must be regular files below `RUN_DIR/artifacts/`. Registration and verification reject absolute paths, traversal, paths outside `artifacts/`, directories, missing files, symlinks, symlinked parent directories, and non-regular files. Stored paths are normalized relative POSIX paths.

SHA-256 is computed with Python standard-library streaming reads so large files are not loaded into memory. Size is derived from the bytes hashed, and the implementation checks file metadata before and after hashing to detect changes when reasonably possible.

Duplicate registered paths are rejected. If an artifact is replaced or updated, the operator must save it under a new path and register the new path.

Evidence verification reads registry records and local artifact files, recomputes SHA-256 and size, and reports verified, missing, mismatch, or unsafe status. Verification does not modify artifacts, `evidence.jsonl`, `manifest.json`, or `run.jsonl`.

Registration requires a valid manifest and durable state stream. Registration is allowed in any valid state except `archived`; archived runs remain listable and verifiable.

## Consequences and limitations

The registry is append-only during normal operation and is durable through flush and `fsync`, but this ADR does not provide a filesystem immutability guarantee. Operators can still alter files with normal filesystem permissions.

No concurrent-writer guarantee is provided. Multiple simultaneous registrations may race and should be serialized by a future coordination layer if needed.

Evidence registration records that an existing local file was observed and hashed. It does not grant authorization, imply approval, perform scope checks, validate findings, or prove collection was authorized.

The evidence layer performs no network activity and does not execute recon.
