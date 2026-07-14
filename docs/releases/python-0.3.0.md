# Outrider Python 0.3.0 release notes

Release date: 2026-07-14

Future tag name: `python-v0.3.0`

Python 0.3.0 is the next Python package release candidate for the completed
local web-control-plane phase. It is not a publication notice; maintainers still
publish tags, GitHub releases, and package artifacts separately.

## Highlights

- Guarded workflow-state transitions through the loopback-only web plane.
- Atomic web run creation with safe server-derived run directories.
- Initialized-only scope replacement, scope checks, and scope-control history.
- Approval grants, revocation, and exact action-policy checks.
- Bounded artifact metadata inventory, registration of existing artifacts as
  evidence, and point-in-time evidence verification.
- Skill-request creation and request/result contract validation without skill
  execution or result upload.
- Explicit human-reviewed finding promotion and finding verification.
- Fixed five-tool MCP catalog, network-free preflight, and explicitly enabled
  transient invocation through the shared policy-gated enrichment module.
- CI split between base Python tests, Python 3.12 web-control tests, and
  release-readiness package validation.

## Optional dependency structure

Base installs remain minimal and require PyYAML only. Optional extras are:

```bash
python -m pip install outrider_recon-0.3.0-py3-none-any.whl
python -m pip install 'outrider_recon-0.3.0-py3-none-any.whl[web]'
python -m pip install 'outrider_recon-0.3.0-py3-none-any.whl[enrichment]'
python -m pip install 'outrider_recon-0.3.0-py3-none-any.whl[mcp]'
python -m pip install 'outrider_recon-0.3.0-py3-none-any.whl[web,enrichment,mcp]'
```

The web extra installs FastAPI, Uvicorn, and HTTPX. Enrichment installs HTTPX.
MCP installs the MCP framework and HTTPX. DNS library support remains optional;
the enrichment code keeps the socket fallback.

## Limitations

The web plane is loopback-only, single-operator, and unauthenticated. The control
token is a local mutation guard, not identity. The release does not add remote
hosting, reverse-proxy deployment, multiuser operation, background jobs, queues,
cancellation, recon orchestration, skill execution, automatic artifact capture,
automatic evidence registration, automatic contract creation, automatic finding
promotion, reports, exports, arbitrary MCP servers, or arbitrary provider
endpoints.

## Artifacts

Expected unsigned candidate artifacts:

- `outrider_recon-0.3.0-py3-none-any.whl`
- `outrider_recon-0.3.0.tar.gz`
- `SHA256SUMS`

Checksum verification:

```bash
grep -E 'outrider_recon-0.3.0-py3-none-any.whl|outrider_recon-0.3.0.tar.gz' SHA256SUMS | sha256sum -c -
```

## Upgrade from 0.2.0

Install the 0.3.0 wheel or sdist in a clean environment and choose only the
extras required for the intended adapter. Existing run schemas remain version 1,
and historical 0.2.0 read-only review-plane artifacts remain readable.
