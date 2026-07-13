# ADR 0012: Web contract controls

## Status

Accepted.

## Context

The local web control plane has bounded controls for run creation, scope, state,
approvals, artifacts, and evidence. The next safe increment is contract handling:
creating policy-checked `skill_request` v1 files and validating existing request
and result contracts without executing skills.

## Decision

The web plane reuses the existing `outrider.skill_contract` domain and the
unchanged v1 request and result schemas. The server generates request IDs,
timestamps, filenames, normalized candidates, and run IDs. Browser input never
supplies output paths, contract paths, request IDs for creation, or raw result
contracts.

Skill requests remain limited to current `REQUEST_ACTIONS`; intrusive and
prohibited action types are excluded. Creation performs current state, scope,
approval, skill, schema, and evidence preflight under the process-local mutation
lock before the atomic request-file replace.

Contract lookup uses embedded UUIDs discovered from safe immediate regular JSON
files beneath `contracts/requests/` and `contracts/results/`. Symlinks,
directories, unsafe entries, malformed files, and duplicate embedded IDs are
reported safely without exposing absolute paths or file contents.

The contract-set revision is a lowercase SHA-256 optimistic inventory token, not
a signature. It covers safe request/result JSON files using deterministic sorting
and length-framed relative POSIX paths and exact bytes. It does not include
state, scope, approval, or evidence registries, so point-in-time validation can
change while the contract revision remains unchanged.

Request validation checks the stored request against current state, scope,
approvals, and evidence. Result validation checks the linked request, referenced
evidence, discovered-candidate scope assessments, and recommended-action policy
assessments. Intrusive recommendations remain handoff-only; no recommendation is
executed. `finding_candidate` remains unpromoted skill output, not a validated
finding.

## Consequences

No skill, Claude, LLM, MCP, DNS, network, subprocess, scanner, or recon execution
is added. No result creation, result upload, contract edit, contract delete,
contract replacement, contract download, finding promotion, report generation,
or artifact transfer is added. Actor values and `created_by` remain
authenticated-by-nobody attribution. The control plane remains loopback-only,
single-operator, unauthenticated, unsuitable for reverse proxies or shared-user
hosting, and unsupported for remote deployment.
