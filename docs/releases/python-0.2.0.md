# Python 0.2.0 release notes

Python 0.2.0 is a minor pre-1.0 release candidate for the Outrider Python control plane. It adds substantial backward-compatible functionality without claiming API stability beyond pre-1.0 expectations.

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

Python remains authoritative for deterministic scope, state, evidence, approval, action-policy, contract, and finding promotion checks. Denied MCP requests must not perform live network or DNS activity.

## Installation from local artifacts

Base install from a downloaded wheel:

```bash
python -m pip install outrider_recon-0.2.0-py3-none-any.whl
```

Optional web review dependencies from a downloaded wheel:

```bash
python -m pip install "outrider_recon-0.2.0-py3-none-any.whl[web]"
```

This release note does not claim that `outrider-recon==0.2.0` has been published to PyPI.

## MCP companion limitation

The MCP server remains an optional source-checkout companion. It is not required for the base wheel and is not advertised as an installed console script in this candidate.

## Supported Python versions

The project CI covers Python 3.10, 3.11, and 3.12.

## Upgrade notes from 0.1.0

Upgrade local wheel installs by replacing the installed 0.1.0 wheel with the 0.2.0 candidate. Existing deterministic run-folder schemas remain version 1.

## Compatibility notes

- Plugin/content version 3.0.1 is a separate domain.
- Individual skill versions remain unchanged.
- JSON schema versions remain at 1.

## Known limitations

- Release publication, Git tags, and GitHub release records are manual maintainer actions.
- Web review is loopback-only and unauthenticated; bind it only to trusted local interfaces.
- MCP enrichment remains optional and source-checkout based.

## Verification commands

```bash
outrider --version
python -m outrider --version
python tools/release_audit.py
python -m twine check dist/*
sha256sum -c dist/SHA256SUMS
```

## Artifact names

- `outrider_recon-0.2.0-py3-none-any.whl`
- `outrider_recon-0.2.0.tar.gz`
- `SHA256SUMS`

## Checksum verification

Place the artifacts and `SHA256SUMS` in the same directory, then run:

```bash
sha256sum -c SHA256SUMS
```
