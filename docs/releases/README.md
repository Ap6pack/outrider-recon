# Outrider release notes

Outrider uses independent version domains:

- Python package releases use the Python distribution version.
- Claude plugin/content releases use `.claude-plugin/plugin.json`.
- Individual skill frontmatter versions are skill-local and did not change for Python 0.3.0 / plugin 3.1.0.
- Runtime JSON schemas and the release manifest schema remain schema version 1.

## Current release candidates

This preparation branch defines unsigned release candidates for future GitHub release records:

- Python package `0.3.0`: tag `python-v0.3.0`, future release page <https://github.com/Ap6pack/outrider-recon/releases/tag/python-v0.3.0>.
- Claude plugin/content `3.1.0`: tag `plugin-v3.1.0`, future release page <https://github.com/Ap6pack/outrider-recon/releases/tag/plugin-v3.1.0>.

The two future tags identify separate release domains. This PR does not create tags, GitHub releases, PyPI publication, or Claude Marketplace publication.

## Candidate artifact assignments

Python release artifacts:

- `outrider_recon-0.3.0-py3-none-any.whl`
- `outrider_recon-0.3.0.tar.gz`
- `SHA256SUMS`

Plugin/content release artifacts:

- `outrider-recon-bundle-3.1.0.zip`
- `SHA256SUMS`

The same `SHA256SUMS` file covers all three release artifacts across the two release domains. If all artifacts from both release pages are downloaded into one artifact directory, run:

```bash
sha256sum -c SHA256SUMS
```

If only the plugin bundle is downloaded, filter to that entry so `sha256sum` does not report the missing Python artifacts:

```bash
grep 'outrider-recon-bundle-3.1.0.zip' SHA256SUMS | sha256sum -c -
```

If only the Python wheel and sdist are downloaded, filter to those entries so `sha256sum` does not report the missing plugin bundle:

```bash
grep -E 'outrider_recon-0.3.0-py3-none-any.whl|outrider_recon-0.3.0.tar.gz' SHA256SUMS | sha256sum -c -
```

An unfiltered `sha256sum -c SHA256SUMS` expects every filename in the checksum file to exist in the current artifact directory.

## Tag namespaces

Current independent tag namespaces are:

- Python: `python-v<python-version>` such as `python-v0.3.0`.
- Plugin/content: `plugin-v<plugin-version>` such as `plugin-v3.1.0`.

For future releases, select unambiguous future tags only after the manual release checklist is complete. Do not reuse or move existing tags.

## Future release order

1. Build and verify unsigned candidates from the selected commit.
2. Create the Python tag if the Python artifacts are accepted.
3. Create the plugin/content tag if the plugin bundle is accepted.
4. Create GitHub release records and attach only the matching artifacts.
5. Optionally publish Python artifacts to PyPI as a separate maintainer action.

## Manual candidate workflow

The manual workflow is `release-candidate.yml` and is triggered with `workflow_dispatch` only. It produces unsigned review outputs for maintainers, keeps `contents: read` permissions, and does not automatically tag, publish GitHub releases, upload to PyPI, or publish to any Claude marketplace. Candidate artifacts are checksum-verifiable; this repository does not claim cryptographic signing for them.

## Verification commands

```bash
python tools/release_audit.py
python -m build
python -m twine check dist/*
python tools/build_release_bundle.py --output-dir dist --source-date-epoch 1783987200
sha256sum -c dist/SHA256SUMS
```
