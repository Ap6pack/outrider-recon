# ADR 0007: Local web review plane

## Context

Operators need a convenient way to review Outrider run identity, state, scope, evidence, approvals, skill contracts, promoted findings, and integrity status without changing the run.

## Decision

Implement a first web-control-plane increment as a read-only, local loopback-only review plane. The CLI requires an explicit runs root and accepts only loopback bind hosts. The implementation separates framework-independent projections in `outrider.web_view` from the optional FastAPI layer in `outrider.web_app`.

The view layer reuses existing deterministic control modules and does not duplicate policy logic. The web layer serves offline packaged static HTML, CSS, and vanilla JavaScript. It exposes only read endpoints, serves no artifact contents, exposes no absolute paths, and does not call mutation helpers.

FastAPI, Uvicorn, and httpx are optional dependencies in the `web` extra. Base non-web commands do not require them.

## Consequences and limitations

The interface has no authentication, no multiuser semantics, and no remote deployment support. It must not be placed behind a public reverse proxy. There is no CSRF model because no writes exist. The plane gives no concurrent-writer guarantee; each request rereads current local files. Future controlled-write work requires a separate security design covering authentication, authorization, CSRF, auditability, and mutation boundaries.
