# ADR 0008: Guarded web workflow-state transitions

## Status

Accepted.

## Context

ADR 0007 introduced a loopback-only read-only web review plane. The first web mutation must be narrow enough to validate a reusable control pattern without adding broader execution capabilities.

## Decision

The local web plane now permits exactly one mutation: transitioning an existing run between valid workflow states. The FastAPI layer resolves a run by UUID beneath the configured runs root, loads current state immediately before mutation, checks an `expected_state` precondition, and delegates all policy and event construction to `outrider.state.load_state` and `outrider.state.transition_state`.

The browser receives allowed next states from the server projection. These options are derived from the deterministic Python state policy and are not authoritative; server-side validation remains the source of truth.

## Mutation guard

Because the server still has no user authentication, each process owns a random control token generated with Python `secrets` unless tests inject a deterministic token. The token is returned only by same-origin `GET /api/session`, kept in JavaScript memory, and required on mutation requests in `X-Outrider-Control-Token`.

Mutation requests are rejected when the token is absent or invalid, when `Sec-Fetch-Site: cross-site` is present, or when an `Origin` header does not match the request origin. CORS remains disabled and cookies are not used.

This token is an anti-CSRF/local mutation capability, not authentication. Any local process running as the same user may still access local files or the loopback service. The server must remain loopback-only and must not be exposed through a reverse proxy.

## Serialization and stale-state behavior

The application instance owns a process-local mutation lock and serializes web mutation requests through it. This prevents concurrent web requests in the same server process from interleaving, but it does not protect against a separate CLI process or another Outrider server process. Operators must not perform simultaneous CLI and web mutations against the same run.

Each transition request includes `expected_state`. If the current state changed before the lock-protected mutation, the API returns a conflict instead of appending an event.

## Audit behavior

Successful transitions append exactly one state event through the existing domain layer. Failed requests do not modify run files.

## Unsupported actions

Run creation, scope editing, approvals, evidence registration, contract mutation, finding promotion, MCP invocation, recon execution, artifact downloads, report generation, and generic action execution remain unsupported in the web plane.

## Consequences

This establishes a reusable guarded mutation pattern while preserving deterministic state policy. The concurrency model is intentionally local and limited; a future multi-process or remote-hosted control plane would require real authentication and stronger locking semantics.
