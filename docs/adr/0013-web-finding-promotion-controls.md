# ADR 0013: Web finding-promotion controls

## Status

Accepted.

## Context

The loopback-only web control plane can now display metadata-only `finding_candidate` claims from stored skill-result contracts and let an operator explicitly promote one selected candidate into one append-only `validated_finding` record. A candidate is a skill output for review; a validated finding is a local human-reviewed classification record. It is not proof of exploitation, authorization, authenticated reviewer identity, client acceptance, impact acceptance, or remediation acceptance.

## Decision

Promotion remains a deliberate human action. The browser never promotes automatically based on confidence, severity, validation status, evidence status, workflow state, scope, or action-policy status. The web layer passes UUIDs and review text to domain functions; it does not construct findings, generate IDs, write `findings.jsonl`, calculate authoritative hashes in JavaScript, execute skills, invoke MCP, upload results, transfer artifacts, export reports, or provide edit/delete controls.

Result and linked-request lookup use safe embedded-ID contract discovery, so filenames do not need to match UUIDs and duplicate IDs are rejected as ambiguous. Source-result SHA-256 is calculated with stable regular-file hashing that rejects symlinks, directories, special files, and files whose identity, size, type, or modification timestamp changes while reading. The reviewed source SHA is an explicit stale-review precondition.

The finding registry revision is the lowercase SHA-256 of exact current `findings.jsonl` bytes, with a missing registry treated as empty bytes. It is an optimistic stale-write token, not a signature. Promotion also checks contract, scope, evidence, and workflow-state revisions under the process-local mutation lock.

Only completed and partial results can be promoted. Blocked and failed results remain visible in inventory but ineligible. Promotion requires verified evidence, current in-scope candidate evaluation, supplementary evidence IDs when supplied, and duplicate result/claim prevention. Records are append-only.

Verification is point-in-time and reports source bytes, source claim snapshot, evidence integrity, and current scope. Scope status is reported separately; existing integrity status precedence is preserved.

## Consequences

The web plane remains loopback-only and unsupported behind reverse proxies. Reviewer attribution is unauthenticated metadata. Process-local locking does not coordinate multiple server processes or simultaneous CLI writes. No edit, delete, export, report generation, result creation/upload, artifact transfer, execution, recon, LLM, Claude, shell, subprocess, or MCP capability is introduced.
