# Outrider release notes

Outrider uses independent version domains:

- Python package release candidates use the Python distribution version.
- Claude plugin/content release candidates use `.claude-plugin/plugin.json`.
- Individual skill frontmatter versions are skill-local and do not change for Python 0.2.0 / plugin 3.0.1.
- Runtime JSON schemas remain schema version 1.

No automatic publication is performed by the release-candidate workflow. Candidate artifacts are unsigned build outputs for maintainer review.

## Recommended tag namespaces

No existing repository tag convention establishes a safe independent version-domain scheme. Use unambiguous future tags after verification:

- Python: `python-v0.2.0`
- Plugin/content: `plugin-v3.0.1`

Do not create these tags until the manual release checklist is complete.

## Release order

1. Build and verify unsigned candidates from the selected commit.
2. Create the Python tag if the Python artifacts are accepted.
3. Create the plugin/content tag if the plugin bundle is accepted.
4. Create GitHub release records and attach only the matching artifacts.
5. Optionally publish Python artifacts to PyPI as a separate maintainer action.

## Artifact naming

- `outrider_recon-0.2.0-py3-none-any.whl`
- `outrider_recon-0.2.0.tar.gz`
- `outrider-recon-bundle-3.0.1.zip`
- `SHA256SUMS`

## Verification commands

```bash
python tools/release_audit.py
python -m build
python -m twine check dist/*
python tools/build_release_bundle.py --output-dir dist --source-date-epoch 1783900800
sha256sum -c dist/SHA256SUMS
```

The manual workflow is `release-candidate.yml` and is triggered with `workflow_dispatch` only.
