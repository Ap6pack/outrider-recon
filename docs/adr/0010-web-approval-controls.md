# ADR 0010: Web approval controls and action-policy checks

## Status

Accepted.

## Context

The local web control plane already supports guarded run creation, initialized-only scope replacement, browser scope checks, and workflow-state transitions. Approval records are the next bounded mutation because the deterministic approval domain already models grant, revocation, exact candidate matching, workflow-state restrictions, scope checks, and permanently prohibited action classes.

## Decision

The web layer exposes approval grants, active-approval revocation, and action-policy evaluation by delegating to `outrider.approval`. It does not write `approvals.jsonl` directly, construct approval events, run skills, invoke MCP, perform recon, make HTTP requests, resolve DNS, validate vulnerabilities, or execute approved actions.

Approval grant accepts duration in minutes only, capped at seven days by the existing approval domain. The browser sends the current workflow state and an exact-file approval-registry revision. The revision is the lowercase SHA-256 digest of the current `approvals.jsonl` bytes; a missing legacy registry is equivalent to empty bytes. It is an optimistic stale-write token, not a signature or authentication mechanism.

The web policy catalog is derived from approval-domain constants. Active and intrusive action types are grantable according to the existing policy. Local and passive actions are evaluable but not grantable. Prohibited action types remain permanently denied and cannot be approved.

Approvals retain exact-match semantics: a grant for one normalized candidate does not approve another candidate, an apex does not approve subdomains, one action type does not approve another, expired or revoked approvals do not authorize, and later scope or workflow-state changes can make a previously approved action deny.

Revocation remains safety-favoring. An active approval can be revoked whenever the approval domain permits it, including after the run leaves a grant-capable state. Revocation appends one event and never renews, edits, or replaces an approval.

Action-policy evaluation calls `evaluate_action` and returns a point-in-time deterministic decision with the current approval revision. It performs no network activity and exposes no control that executes the evaluated action.

## Consequences

Approval mutations serialize through the web app's process-local mutation lock and stale revision checks. This prevents two approval web mutations in the same process from both succeeding with the same revision, but it does not protect against another web server process, simultaneous CLI mutation, or direct file editing. Operators must avoid simultaneous CLI and web mutations against the same run.

The process-local token and same-origin checks are CSRF-style safeguards for a loopback-only single-operator tool; they are not user authentication. Approval actor values are unauthenticated attribution metadata. An approval record is not proof of written authorization, proof that the candidate remains in scope, proof that the workflow state remains valid, permission for a prohibited action, or automatic permission to execute anything.

The web plane remains unsuitable for reverse proxies, shared-user hosting, remote deployment, cookies, CORS, multiuser behavior, or authenticated approval identity. Evidence registration, artifact transfer, skill request/result creation, finding promotion, MCP invocation, recon execution, command execution, report generation, approval editing, renewal, and batch approval operations remain unsupported.
