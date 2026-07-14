# Manual release checklist

This checklist is reusable for future maintainer-operated releases. The post-release documentation cleanup does not recreate releases, retag commits, replace artifacts, publish to external registries, or modify release records.

## Completed release record: 2026-07-13

- Python package `0.3.0` was released from commit `2ff9db995e7d2cb78024cbeea09bf526888626da` with tag `python-v0.3.0` and a GitHub release record.
- Claude plugin/content `3.1.0` was released from the same commit with tag `plugin-v3.1.0` and a GitHub release record.
- Published artifacts were accepted as `outrider_recon-0.3.0-py3-none-any.whl`, `outrider_recon-0.3.0.tar.gz`, `outrider-recon-bundle-3.1.0.zip`, and shared `SHA256SUMS`.
- Checksum verification passed for all three release artifacts.
- Clean base-wheel installation passed, and `outrider --version` plus `python -m outrider --version` reported `outrider-recon 0.3.0`.
- Clean optional web installation passed, including installed-wheel FastAPI TestClient checks for `/api/health`, `/`, `/static/app.css`, and `/static/app.js`.
- PyPI publication is not marked complete.
- Claude Marketplace publication is not marked complete.

## Future release checklist

### 1. Pre-tag verification

- Confirm the selected commit is on `main` and CI has passed.
- Run `python tools/release_audit.py` and review limitations.
- Confirm the intended Python, plugin/content, skill, runtime schema, and release manifest schema versions.

### 2. Build unsigned candidate artifacts

- Run the manual release-candidate workflow or build locally.
- Build wheel, sdist, plugin/content bundle, and `SHA256SUMS`.
- Treat workflow artifacts as unsigned maintainer-review outputs, not automatic publications.

### 3. Inspect artifacts

- Inspect wheel and sdist metadata.
- Inspect the plugin/content zip contents and `RELEASE-MANIFEST.json`.
- Confirm no tests, CI, caches, run data, credentials, or local artifacts are present.

### 4. Verify checksums

- Run `sha256sum -c SHA256SUMS` in the artifact directory when all artifacts are present.
- Use filtered checksum commands when only one release domain's artifacts are present.

### 5. Create release tags

- Create the Python tag from the verified commit only after Python artifacts are accepted.
- Create the plugin/content tag from the verified commit only after the plugin/content bundle is accepted.
- Do not move existing release tags for documentation-only follow-up commits.

### 6. Create GitHub release records

- Create release records after tags exist.
- Attach only the artifacts that match each release domain plus the shared checksum file.

### 7. Optional external publication

- Publish to PyPI only after maintainer approval using secure external publishing configuration.
- Publish to any Claude marketplace only after maintainer approval and marketplace-specific verification.
- Do not store credentials or tokens in repository files.

### 8. Post-release installation verification

- Install the published wheel in clean base and web environments.
- Verify CLI and module version commands.
- Smoke-test installed optional web resources when web extras are published.

### 9. Documentation verification

- Confirm documentation distinguishes published GitHub releases from future unsigned release-candidate builds.
- Confirm PyPI and marketplace publication are claimed only if independently completed.

### 10. Rollback response

- If a release error is found, document affected artifacts, remove or supersede broken release records as appropriate, and publish corrected artifacts from a new verified commit.
