# Outrider Claude plugin/content 3.1.0 release notes

Release date: 2026-07-14

Future tag name: `plugin-v3.1.0`

Plugin/content 3.1.0 is the next installable content bundle candidate. It is not
a publication notice; maintainers still publish tags and release assets
separately. Python 0.3.0 is a separate version domain included in the bundle.

## Highlights

- Bundle metadata is updated to plugin/content version 3.1.0.
- The bundle includes Python 0.3.0 package sources and packaged static web UI
  resources for the completed local control plane.
- The shared MCP companion server and documentation are updated for the fixed
  five-tool policy-gated enrichment catalog.
- Plugin metadata now describes deterministic Python controls, the optional
  loopback-only limited-control web plane, human-reviewed finding promotion, and
  optional fixed MCP enrichment without claiming autonomous recon orchestration.
- The 11-skill catalog is unchanged.
- Individual skill frontmatter versions are unchanged.
- Capability count remains 90 documented capabilities.
- Manifest, runtime, evidence, approval, skill-request, skill-result, and finding
  schema versions remain version 1.

## Bundle artifact

Expected unsigned candidate artifact:

- `outrider-recon-bundle-3.1.0.zip`
- `SHA256SUMS`

Checksum verification:

```bash
grep 'outrider-recon-bundle-3.1.0.zip' SHA256SUMS | sha256sum -c -
```

## Upgrade from 3.0.1

Install or unpack the 3.1.0 bundle over the previous plugin/content bundle using
the repository installation instructions. Do not create the future
`plugin-v3.1.0` tag until maintainers intentionally publish the release.
