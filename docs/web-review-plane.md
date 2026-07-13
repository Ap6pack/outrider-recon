# Local web review plane

The local web review plane is an optional, limited-control interface for reviewing existing Outrider runs and applying guarded workflow-state transitions. It is intended for a single operator on the local machine.

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

The web plane has exactly one mutation capability: `POST /api/runs/{run_id}/state/transition`. It transitions an existing run between valid workflow states by calling the Python state layer. The web layer does not modify `run.jsonl` directly, duplicate transition rules, invoke the CLI, or construct state events.

The web plane does not create runs, edit scope, execute skills, invoke MCP, perform recon, grant or revoke approvals, register evidence, mutate contracts, promote findings, generate reports, execute generic actions, or serve artifact contents. Those actions remain CLI-only or unsupported.

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
