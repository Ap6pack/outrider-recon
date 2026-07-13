# Claude plugin/content 3.0.1 release notes

Claude plugin/content 3.0.1 is a published GitHub release for the existing 3.0 methodology and capability set. It corrects metadata and documentation boundaries without changing individual skill methodology.

- Release tag: `plugin-v3.0.1`
- Release page: <https://github.com/Ap6pack/outrider-recon/releases/tag/plugin-v3.0.1>
- Release commit: `2ff9db995e7d2cb78024cbeea09bf526888626da`
- Published artifact: `outrider-recon-bundle-3.0.1.zip`
- Shared checksum artifact: `SHA256SUMS`

## Scope of the patch

- Plugin metadata reports `3.0.1`.
- The bundle documents 11 shipped skills; `skills/_shared` is shared guidance and is not counted as a twelfth skill.
- The existing capability count is unchanged.
- Individual skill frontmatter versions did not change.
- Python 0.2.0 is a separate version domain and no PyPI publication is implied by this plugin/content release.
- No Claude Marketplace publication is claimed.

## Published release verification

A GitHub release exists for `plugin-v3.0.1`. Maintainer verification confirmed checksum verification for `outrider-recon-bundle-3.0.1.zip` and accepted the `RELEASE-MANIFEST.json` contents for the 11-skill bundle.

## Structured-run guidance

Skills continue to use shared structured-run contract guidance. Discovery signals do not expand scope, and skills may produce `finding_candidate` records but must not claim Python-validated findings. Skills cannot self-certify `validated_finding` records.

## Deterministic-control relationship

The Claude plugin/content describes methodology. The Python control plane remains authoritative for deterministic scope, state, evidence, approval, MCP guard, contract, and finding checks.

## Optional MCP relationship

MCP enrichment remains optional and guarded. It must honor Python policy decisions and does not expand scope.

## Local web relationship

The optional local web plane is read-only, loopback-oriented review UI for local run data. It does not mutate runs or publish artifacts.

## Installation and update

Download the plugin/content bundle from the 3.0.1 GitHub release page:

- `outrider-recon-bundle-3.0.1.zip`

Extract it into a review directory, inspect `RELEASE-MANIFEST.json`, and follow the repository installation guide for the Claude surface you use.

## Known limitations

- Published artifacts are checksum-verifiable but are not claimed to be cryptographically signed.
- MCP remains a source-checkout companion.
- No Claude Marketplace publication is claimed.

## Checksum verification

The same `SHA256SUMS` file covers all three artifacts across the Python and plugin/content release domains. If all artifacts from both release pages are present in the current artifact directory, run:

```bash
sha256sum -c SHA256SUMS
```

If only the plugin bundle is present, filter to the bundle entry so the Python artifacts are not reported as missing:

```bash
grep 'outrider-recon-bundle-3.0.1.zip' SHA256SUMS | sha256sum -c -
```
