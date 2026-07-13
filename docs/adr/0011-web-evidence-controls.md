# ADR 0011: Web evidence controls

## Status

Accepted.

## Context

The local web control plane already supports bounded run, scope, state, approval,
and action-policy controls. Existing-file evidence registration is the next
bounded mutation because the Python evidence domain already defines deterministic
path normalization, symlink refusal, regular-file checks, duplicate-path refusal,
archived-run refusal, hashing, size recording, append-only records, and
point-in-time verification.

## Decision

The web layer delegates evidence registration and verification to
`outrider.evidence`. It does not write `evidence.jsonl` directly, construct
records, calculate hashes in JavaScript, invoke the CLI, upload artifacts, serve
artifact contents, preview artifacts, or provide artifact downloads.

The browser can list bounded metadata-only artifact candidates beneath the
configured run's `artifacts/` directory. Inventory returns canonical relative
paths, sizes, registration status, and evidence IDs when already registered. It
refuses or skips symlinks, symlink directories, directories, and special files,
never follows symlinks, never opens contents, imposes a file-count limit and a
recursion-depth limit, and reports truncation and skipped counts. Inventory is a
point-in-time convenience view; direct external filesystem races are acceptable
because registration revalidates authoritatively.

Evidence registration accepts only an existing canonical relative path beneath
`artifacts/`, operator-provided attribution metadata, the displayed workflow
state, and the exact evidence-registry revision. The server/domain generates the
UUID, sequence, timestamp, hash, and size. The revision is the lowercase SHA-256
of exact current `evidence.jsonl` bytes; a missing legacy registry is equivalent
to empty bytes. It is an optimistic stale-write token, not a signature.

Registration is refused for stale workflow state, stale evidence revision,
archived runs, duplicate paths, unsafe paths, missing files, directories,
symlinks, symlink parents, special files, and files that change while hashing.
Successful registration appends one record and does not change workflow state or
artifact bytes.

Verification can check one registered evidence UUID or all records. It is a
point-in-time byte-integrity operation that returns verified, mismatch, missing,
or unsafe statuses and deterministic counts. Verification does not update the
registry, timestamps, expected hashes, or artifacts; it does not repair,
re-register, or replace evidence. A verified result proves byte consistency only,
not truth, security significance, authorization, vulnerability, source identity,
or finding validity. Later artifact modification creates a mismatch.

The process-local mutation lock serializes web registration and verification
snapshots within one server process. It does not protect against another web
server process, simultaneous CLI registration, direct registry edits, or direct
artifact modification. Existing hashing continues to detect changes during read.

Actor values are unauthenticated attribution, not authenticated identities. The
process-local token and same-origin checks are local CSRF-style safeguards, not
user authentication.

The web plane remains loopback-only, single-operator, unauthenticated, unsuitable
for reverse proxies, shared-user hosting, remote deployment, cookies, CORS, or
multiuser behavior. Artifact upload/download/preview/content serving, evidence
edit/delete/replacement, contracts, findings, MCP invocation, recon execution,
command execution, and remote hosting remain unsupported.
