# Local web review plane

The local web review plane is an optional, read-only interface for reviewing existing Outrider runs. It is intended for a single operator on the local machine.

## Architecture

The implementation is split into two layers:

- `outrider.web_view` discovers immediate child run folders under an explicit runs root and builds JSON-serializable projections. It has no FastAPI dependency and no network behavior.
- `outrider.web_app` creates the optional FastAPI application, serves packaged static assets, and exposes same-origin read-only JSON endpoints.

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

## Read-only boundaries

The web plane does not mutate run data, execute skills, invoke MCP, perform recon, grant or revoke approvals, transition state, register evidence, promote findings, modify scope, or serve artifact contents. Future controlled-write features are intentionally deferred.

## Loopback restriction

The CLI permits only `127.0.0.1`, `localhost`, or `::1` and rejects wildcard, LAN, public, and arbitrary hostnames. There is no override in this increment.

## Filesystem discovery and path safety

Only immediate child directories beneath the runs root are considered. Symlinked roots are rejected; symlinked run directories and symlinked contract files are skipped. Valid runs are identified by `manifest.json`; duplicate run IDs are reported as errors and not silently selected. API callers pass run UUIDs, never filesystem paths. Responses avoid absolute paths and authorization references.

## Security headers

The app sends a self-only Content Security Policy, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Cache-Control: no-store` for API responses. CORS is not enabled.

## Data not exposed

Artifact contents, contract raw JSON contents, environment variables, Python tracebacks, arbitrary files, and absolute local paths are not exposed. Static serving is limited to packaged web assets.

## Limitations and troubleshooting

Install the `web` extra if `outrider web serve` reports missing web dependencies. Use the CLI for all authoritative control actions. This release has no authentication, no multiuser semantics, no remote-hosting support, and no concurrent-writer guarantee.
