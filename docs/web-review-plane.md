# Local web review plane

The local web review plane is an optional, limited-control interface for reviewing existing Outrider runs and applying guarded workflow-state transitions, guarded run creation, initialized-only scope replacement, and browser scope checks. It is intended for a single operator on the local machine.

## Architecture

The implementation is split into two layers:

- `outrider.web_view` discovers immediate child run folders under an explicit runs root and builds JSON-serializable projections. It has no FastAPI dependency and no network behavior.
- `outrider.web_app` creates the optional FastAPI application, serves packaged static assets, and exposes same-origin JSON endpoints, including one guarded state-transition mutation endpoint.

The projection layer reuses existing state, scope, evidence, approval, skill-contract, and finding modules instead of reimplementing control policy.

## Optional dependencies and startup

Install with:

```bash
python -m pip install -e ".[web]"
outrider web serve ./runs
```

The default URL is `http://127.0.0.1:8765`.

## Dashboard and detail views

The dashboard lists run target, workflow state, evidence count, active approval count, contract counts, finding count, and health. Detail tabs cover overview, scope, state, evidence, approvals, contracts, findings, and integrity.

## Mutation boundary

The web plane supports guarded run creation, initialized-only scope management, scope checks, workflow-state transitions, approval grant/revocation, action-policy checks, bounded artifact metadata inventory, existing-artifact evidence registration, and evidence-integrity verification. State transitions call the Python state layer; evidence registration calls the Python evidence layer. The web layer does not modify `run.jsonl` or `evidence.jsonl` directly, duplicate domain rules, invoke the CLI, or construct state/evidence events.

The web plane remains limited-control. It does not upload, preview, download, serve, edit, or delete artifact contents; it does not edit/delete evidence, mutate contracts, promote findings, invoke MCP, run recon, generate reports, or execute generic actions.

## Loopback restriction

The CLI permits only `127.0.0.1`, `localhost`, or `::1` and rejects wildcard, LAN, public, and arbitrary hostnames. There is no override in this increment.

## Filesystem discovery and path safety

Only immediate child directories beneath the runs root are considered. Symlinked roots are rejected; symlinked run directories and symlinked contract files are skipped. Valid runs are identified by `manifest.json`; duplicate run IDs are reported as errors and not silently selected. API callers pass run UUIDs, never filesystem paths. Responses avoid absolute paths and authorization references.

## Control token and request checks

Because the interface has no user authentication, the server creates a process-local control token at startup. `GET /api/session` returns that token with `Cache-Control: no-store`; the browser keeps it only in JavaScript memory and sends it on mutation requests using `X-Outrider-Control-Token`. The token is an anti-CSRF/local mutation capability, not authentication. It is not written to disk, printed by the CLI, embedded in static assets, or stored in browser storage.

Mutation requests with a missing or invalid token return `403`. Requests with `Sec-Fetch-Site: cross-site` or a mismatched `Origin` header also return `403`. CORS is not enabled and cookies are not used.

Any local process acting as the same user may still access local files or the loopback service. The server must remain loopback-only and must not be exposed through a reverse proxy.

## Concurrency limit

A process-local lock serializes web mutations inside one application instance. This does not coordinate with separate CLI processes or other Outrider web server processes. Operators must not perform simultaneous CLI and web mutations against the same run.

## Security headers

The app sends a self-only Content Security Policy, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Cache-Control: no-store` for API responses. CORS is not enabled.

## Data not exposed

Artifact contents, contract raw JSON contents, environment variables, Python tracebacks, arbitrary files, and absolute local paths are not exposed. Static serving is limited to packaged web assets.

## Limitations and troubleshooting

Install the `web` extra if `outrider web serve` reports missing web dependencies. Use the CLI for all authoritative control actions. This release has no authentication, no multiuser semantics, no remote-hosting support, and no cross-process concurrent-writer guarantee.

## Guarded approval controls and action-policy checks

The Approvals tab now contains three browser controls: action-policy check, bounded approval grant, and active-approval revocation. These controls reuse `outrider.approval` for candidate normalization, scope evaluation, workflow-state policy, exact matching approvals, duplicate prevention, expiration, and append-only registry writes.

Approval grants require the process-local control token, same-origin checks, the current workflow state, and the exact `approvals.jsonl` SHA-256 revision. The revision is an optimistic stale-write token calculated from registry bytes; it is not a signature and does not authenticate the operator. Missing legacy registries are treated as empty bytes, and merely reading the revision does not create a file.

The web API accepts duration in minutes only, with the existing seven-day maximum. It does not accept arbitrary expiration timestamps. Local, passive, and prohibited action categories cannot be granted; prohibited action categories remain permanently denied.

Action-policy checks call `evaluate_action` and return a point-in-time decision for the current state, scope, and exact matching approval status. A browser allow decision does not execute anything and creates no evidence, findings, contracts, MCP calls, recon, DNS lookups, HTTP requests, or artifacts.

Approvals are exact-match records. An approval for `api.example.com` does not approve `other.example.com`, an apex approval does not approve subdomains, an approval for one action type does not approve another, and expired or revoked approvals do not authorize. Scope or workflow-state changes can cause a previously approved candidate to deny.

Active approvals can be revoked through the browser with the same token, origin, mutation-lock, and revision guard. Revocation appends one event, does not require a grant-capable workflow state, and never renews or edits an approval.

The mutation lock is process-local. Revision checks serialize guarded web mutations within one app process, but operators must avoid simultaneous CLI and web mutations, multiple web server processes, and direct registry edits against the same run.


## Finding candidate review

The web plane lists metadata-only `finding_candidate` claims, supports explicit human promotion into append-only `validated_finding` records, and verifies findings point-in-time against source result bytes, source claim snapshots, evidence integrity, and current scope. It does not automatically promote, edit, delete, export, generate reports, execute skills, invoke MCP, upload results, or transfer artifacts.
