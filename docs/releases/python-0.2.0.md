# Python 0.2.0 release notes

Python 0.2.0 is a minor pre-1.0 GitHub release for the Outrider Python control plane. It adds substantial backward-compatible functionality without claiming stable post-1.0 API guarantees.

- Release tag: `python-v0.2.0`
- Release page: <https://github.com/Ap6pack/outrider-recon/releases/tag/python-v0.2.0>
- Release commit: `2ff9db995e7d2cb78024cbeea09bf526888626da`
- Published artifacts: `outrider_recon-0.2.0-py3-none-any.whl`, `outrider_recon-0.2.0.tar.gz`, and `SHA256SUMS`

## Verification results

Maintainer verification confirmed that checksum verification passed for the wheel and source distribution, the base wheel installed successfully in a clean Python 3.12 environment, and both commands reported `outrider-recon 0.2.0`:

```bash
outrider --version
python -m outrider --version
```

The optional web installation also succeeded in a clean environment, and installed-wheel FastAPI TestClient checks passed for `/api/health`, `/`, `/static/app.css`, and `/static/app.js`.

## Major features

- Deterministic scope validation and default-deny scope decisions.
- Durable run identity, manifests, and workflow state.
- Evidence registration and integrity verification.
- Approval records and action-policy decisions.
- MCP guard integration for source-checkout companion services.
- Structured skill request/result contracts.
- Deterministic finding promotion.
- Optional local loopback-only web review.
- Packaged skill catalog, schemas, and web resources.
- Clean-install and release-readiness tooling.

## Security and control boundaries

Python remains authoritative for deterministic scope, state, evidence, approval, action-policy, contract, and finding promotion checks. Denied MCP requests must not perform live network or DNS activity. Python does not execute the recon methodology itself.

## Installation from GitHub release artifacts

Download the wheel from the Python 0.2.0 GitHub release page into an artifact directory, then install it directly:

```bash
python -m pip install ./outrider_recon-0.2.0-py3-none-any.whl
```

Optional web review dependencies can be installed from the downloaded wheel with:

```bash
python -m pip install "./outrider_recon-0.2.0-py3-none-any.whl[web]"
```

This release note does not claim PyPI availability for `outrider-recon==0.2.0`.

## MCP companion limitation

The MCP server remains an optional source-checkout companion. It is not required for the base wheel and is not advertised as an installed console script.

## Supported Python versions

The project CI covers Python 3.10, 3.11, and 3.12. Clean-install release verification was confirmed with Python 3.12.

## Upgrade notes from 0.1.0

Upgrade local wheel installs by replacing the installed 0.1.0 wheel with the downloaded 0.2.0 wheel. Existing deterministic run-folder schemas remain version 1.

## Compatibility notes

- Plugin/content version 3.0.1 is a separate domain.
- Individual skill versions remain unchanged.
- JSON schema versions remain at 1.

## Known limitations

- Future release publication, tags, and GitHub release records remain maintainer-operated actions.
- Web review is loopback-only and unauthenticated; bind it only to trusted local interfaces.
- MCP enrichment remains optional and source-checkout based.
- Published artifacts are checksum-verifiable but are not claimed to be cryptographically signed.

## Checksum verification

The same `SHA256SUMS` file covers all three artifacts across the Python and plugin/content release domains. If all artifacts from both release pages are present in the current artifact directory, run:

```bash
sha256sum -c SHA256SUMS
```

If only the Python artifacts are present, filter to the wheel and sdist entries so the plugin bundle is not reported as missing:

```bash
grep -E 'outrider_recon-0.2.0-py3-none-any.whl|outrider_recon-0.2.0.tar.gz' SHA256SUMS | sha256sum -c -
```
