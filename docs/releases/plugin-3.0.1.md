# Claude plugin/content 3.0.1 release notes

Claude plugin/content 3.0.1 is a patch release candidate for the existing 3.0 methodology and capability set. It corrects metadata and documentation boundaries without changing individual skill methodology.

## Scope of the patch

- Plugin metadata reports `3.0.1`.
- The bundle documents 11 shipped skills; `skills/_shared` is shared guidance and is not counted as a twelfth skill.
- The existing capability count is unchanged.
- Individual skill frontmatter versions did not change.
- Python 0.2.0 is a separate version domain.

## Structured-run guidance

Skills continue to use shared structured-run contract guidance. Discovery signals do not expand scope, and skills may produce `finding_candidate` records but must not claim Python-validated findings.

## Deterministic-control relationship

The Claude plugin/content describes methodology. The Python control plane remains authoritative for deterministic scope, state, evidence, approval, MCP guard, contract, and finding checks.

## Optional MCP relationship

MCP enrichment remains optional and guarded. It must honor Python policy decisions and does not expand scope.

## Local web relationship

The optional local web plane is read-only, loopback-oriented review UI for local run data. It does not mutate runs or publish artifacts.

## Installation and update

Use the plugin/content bundle artifact:

- `outrider-recon-bundle-3.0.1.zip`

Extract it into a review directory, inspect `RELEASE-MANIFEST.json`, and follow the repository installation guide. Do not treat the unsigned candidate as an official release until maintainers create the appropriate tags and release records.

## Known limitations

- Candidate artifacts are unsigned.
- No Git tag, GitHub release, PyPI upload, or plugin publication is performed by this preparation PR.
- MCP remains a source-checkout companion.

## Checksum verification

```bash
sha256sum -c SHA256SUMS
```
