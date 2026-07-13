# Manual release checklist

This checklist is for a future maintainer-operated release. This PR does not perform tagging, publication, GitHub release creation, PyPI upload, or plugin publication.

## 1. Pre-tag verification

- Confirm the selected commit is on `main` and CI has passed.
- Run `python tools/release_audit.py` and review limitations.
- Confirm Python `0.2.0`, plugin/content `3.0.1`, 11 skills, and schema version 1.

## 2. Build candidate artifacts

- Run the manual release-candidate workflow or build locally.
- Build wheel, sdist, plugin/content bundle, and `SHA256SUMS`.

## 3. Inspect artifacts

- Inspect wheel and sdist metadata.
- Inspect `outrider-recon-bundle-3.0.1.zip` contents and `RELEASE-MANIFEST.json`.
- Confirm no tests, CI, caches, run data, credentials, or local artifacts are present.

## 4. Verify checksums

- Run `sha256sum -c SHA256SUMS` in the artifact directory.

## 5. Create Python tag

- After acceptance, create `python-v0.2.0` from the verified commit.

## 6. Create plugin/content tag

- After acceptance, create `plugin-v3.0.1` from the verified commit.

## 7. Create GitHub release or releases

- Create release records after tags exist.
- Mark candidates appropriately if not final.

## 8. Attach correct artifacts

- Attach Python artifacts to the Python release record.
- Attach plugin/content bundle and checksums to the plugin/content release record.

## 9. Optional PyPI publication

- Publish only after maintainer approval using secure external publishing configuration.
- Do not store credentials or tokens in repository files.

## 10. Post-release installation verification

- Install the published wheel in clean base and web environments.
- Verify `outrider --version` reports `0.2.0`.

## 11. Documentation verification

- Confirm documentation no longer describes accepted artifacts as unpublished candidates once publication actually occurs.

## 12. Rollback response

- If a release error is found, document affected artifacts, remove or supersede broken release records as appropriate, and publish corrected artifacts from a new verified commit.
