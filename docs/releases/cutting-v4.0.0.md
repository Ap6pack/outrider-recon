# Cutting the v4.0.0 release

A version-specific runbook for the first unified release. These are manual
maintainer steps; the repository never creates tags or GitHub releases
automatically. See [release-checklist.md](release-checklist.md) for the reusable
generic checklist and [README.md](README.md) for artifact and checksum details.

`4.0.0` is the first unified version: the Python package and the Claude
plugin/content bundle share one number and ship under one `v4.0.0` tag.

## 0. Prerequisite — land the version on `main` first

The tag must point at a `main` commit that already reports `4.0.0`, so merge the
version-unification PR first, then confirm the checkout:

```bash
git checkout main
git pull --ff-only origin main
python tools/release_audit.py            # expect: Overall status: ready
grep '^version' pyproject.toml           # expect: version = "4.0.0"
```

## 1. Produce the artifacts

### Path A — recommended (the manual candidate workflow)

Runs the same build the audit expects and uploads the reviewed candidates:

```bash
gh workflow run release-candidate.yml --ref main
RUN_ID="$(gh run list --workflow=release-candidate.yml --branch main --limit 1 --json databaseId -q '.[0].databaseId')"
gh run watch "$RUN_ID"
mkdir -p dist
gh run download "$RUN_ID" -n outrider-release-candidates-4.0.0 -D dist
```

### Path B — build locally instead

Uses the same `--source-date-epoch` as CI so the bundle is reproducible:

```bash
rm -rf dist build ./*.egg-info
python -m build
python tools/build_release_bundle.py --output-dir dist --source-date-epoch 1783987200
( cd dist && sha256sum \
    outrider_recon-4.0.0-py3-none-any.whl \
    outrider_recon-4.0.0.tar.gz \
    outrider-recon-bundle-4.0.0.zip | sort -k2 > SHA256SUMS )
```

## 2. Verify the checksums

```bash
( cd dist && sha256sum -c SHA256SUMS )   # expect: all "OK"
ls dist/                                 # 3 artifacts + SHA256SUMS
```

## 3. Create the annotated tag

```bash
git tag -a v4.0.0 -m "Outrider 4.0.0 — first unified release"
git push origin v4.0.0
```

## 4. Create the GitHub release

Attach all three artifacts plus the shared checksum file, using the 4.0.0 note as
the release body:

```bash
gh release create v4.0.0 \
  dist/outrider_recon-4.0.0-py3-none-any.whl \
  dist/outrider_recon-4.0.0.tar.gz \
  dist/outrider-recon-bundle-4.0.0.zip \
  dist/SHA256SUMS \
  --title "Outrider 4.0.0" \
  --notes-file docs/releases/4.0.0.md \
  --verify-tag
```

## 5. Optional — publish the Python package to PyPI

This is opt-in and separate. The release documentation does not claim PyPI
publication until it is actually done, and the release audit fails on premature
"published to PyPI" claims. Supply your own credentials through your PyPI
configuration; do not store them in the repository:

```bash
python -m twine check dist/outrider_recon-4.0.0*
python -m twine upload dist/outrider_recon-4.0.0-py3-none-any.whl dist/outrider_recon-4.0.0.tar.gz
```

If you publish, update `docs/installation.md` and `docs/releases/` to reflect it.

## Notes

- Order matters: merge, then tag on `main`. Tagging the PR branch would point
  `v4.0.0` at the wrong commit.
- Use an annotated tag (`git tag -a`). Creating it with `git` first and passing
  `--verify-tag` keeps `gh release create` from making a lightweight tag.
- Do not move the tag later for documentation-only follow-up commits.
- Once `v4.0.0` exists, the CHANGELOG compare links
  (`v4.0.0...HEAD`, `plugin-v3.1.0...v4.0.0`) and the `releases/tag/v4.0.0` links
  in the docs all resolve.
- Historical `python-v*` and `plugin-v*` tags and release notes are retained as
  immutable history and are not reused or moved.
