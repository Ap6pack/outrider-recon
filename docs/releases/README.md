# Outrider release notes

Outrider ships as a single product under one unified version:

- The Python package version (`pyproject.toml`) and the Claude plugin/content bundle version (`.claude-plugin/plugin.json`) are the same number.
- Individual skill frontmatter versions are skill-local and are not bumped per release; skill content ships with the unified release.
- Runtime JSON schemas and the release manifest schema remain schema version 1.

Historical releases used separate `python-v*` and `plugin-v*` version lines; the per-domain notes in this directory are retained as accurate history.

Outrider `4.0.0` is published: a GitHub release at [`v4.0.0`](https://github.com/Ap6pack/outrider-recon/releases/tag/v4.0.0) and on PyPI as [`outrider-recon`](https://pypi.org/project/outrider-recon/).

## Current release candidates

This preparation branch defines an unsigned release candidate for a future GitHub release record:

- Outrider `4.0.0`: tag `v4.0.0`, future release page <https://github.com/Ap6pack/outrider-recon/releases/tag/v4.0.0>.

This is the first unified release, superseding the earlier separate Python `0.3.0` and plugin/content `3.1.0` lines. This PR does not create tags, GitHub releases, PyPI publication, or Claude Marketplace publication.

## Candidate artifact assignments

The unified `4.0.0` release ships three artifacts under one tag:

- `outrider_recon-4.0.0-py3-none-any.whl`
- `outrider_recon-4.0.0.tar.gz`
- `outrider-recon-bundle-4.0.0.zip`
- `SHA256SUMS`

The same `SHA256SUMS` file covers all three release artifacts. If all artifacts are downloaded into one artifact directory, run:

```bash
sha256sum -c SHA256SUMS
```

If only the plugin/content bundle is downloaded, filter to that entry so `sha256sum` does not report the missing Python artifacts:

```bash
grep 'outrider-recon-bundle-4.0.0.zip' SHA256SUMS | sha256sum -c -
```

If only the Python wheel and sdist are downloaded, filter to those entries so `sha256sum` does not report the missing bundle:

```bash
grep -E 'outrider_recon-4.0.0-py3-none-any.whl|outrider_recon-4.0.0.tar.gz' SHA256SUMS | sha256sum -c -
```

An unfiltered `sha256sum -c SHA256SUMS` expects every filename in the checksum file to exist in the current artifact directory.

## Tag namespace

The unified tag namespace is `v<version>`, such as `v4.0.0`. Historical tags (`python-v0.3.0`, `plugin-v3.1.0`, and earlier) are retained as immutable history and are not reused or moved.

## Future release order

1. Build and verify unsigned candidates from the selected commit.
2. Create the unified `v<version>` tag once the wheel, sdist, and bundle are accepted.
3. Create the GitHub release record and attach all three artifacts plus the shared `SHA256SUMS`.
4. Optionally publish the Python artifacts to PyPI as a separate maintainer action.

## Manual candidate workflow

The manual workflow is `release-candidate.yml` and is triggered with `workflow_dispatch` only. It produces unsigned review outputs for maintainers, keeps `contents: read` permissions, and does not automatically tag, publish GitHub releases, upload to PyPI, or publish to any Claude marketplace. Candidate artifacts are checksum-verifiable; this repository does not claim cryptographic signing for them.

PyPI publishing is handled separately by `publish-pypi.yml`, which uses PyPI Trusted Publishing (OIDC) — no API token or repository secret — and runs on `release: published` or `workflow_dispatch`.

## Verification commands

```bash
python tools/release_audit.py
python -m build
python -m twine check dist/*
python tools/build_release_bundle.py --output-dir dist --source-date-epoch 1783987200
sha256sum -c dist/SHA256SUMS
```
