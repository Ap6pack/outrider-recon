# Release-readiness audit

- **Audit date:** 2026-07-13
- **Audited commit:** 57b452d4688cac280f17f3d35867e9129dc3706e plus this audit branch's committed changes
- **Overall status:** ready_with_limitations

## Post-release status

After the historical audit below, maintainers completed the release from commit `2ff9db995e7d2cb78024cbeea09bf526888626da`. Python `0.2.0` is published as GitHub release tag `python-v0.2.0` (<https://github.com/Ap6pack/outrider-recon/releases/tag/python-v0.2.0>), and Claude plugin/content `3.0.1` is published as GitHub release tag `plugin-v3.0.1` (<https://github.com/Ap6pack/outrider-recon/releases/tag/plugin-v3.0.1>). Both tags point to the release commit.

Maintainer verification confirmed successful checksum verification for `outrider_recon-0.2.0-py3-none-any.whl`, `outrider_recon-0.2.0.tar.gz`, and `outrider-recon-bundle-3.0.1.zip`; successful clean base-wheel installation; successful optional web installation; and installed-wheel FastAPI TestClient checks for `/api/health`, `/`, `/static/app.css`, and `/static/app.js`. PyPI publication is not claimed. Claude Marketplace publication is not claimed. Published artifacts are checksum-verifiable but are not claimed to be cryptographically signed.

## Supported execution modes

| Mode | Status | Notes |
| --- | --- | --- |
| Claude skill/content bundle | ready_with_limitations | 11 shipped skills plus `_shared` contract guidance; skills provide methodology and do not bypass deterministic controls. |
| Base Python CLI | ready | Package version remains `0.2.0`; base runtime depends on PyYAML and provides deterministic run, scope, state, evidence, approval, contract, finding, and discoverability commands. |
| Optional MCP server | ready_with_limitations | Source-checkout companion with five guarded tools; not included as a base wheel dependency. |
| Optional local web review plane | ready_with_limitations | Installed with `.[web]`; loopback-only, read-only, no artifact download route, no write route, no Node build. |

## Python package status

Status: **ready**. The package builds as a wheel and source distribution with Python modules, package metadata, LICENSE, README, packaged skill catalog metadata, packaged JSON schemas, and packaged static web assets. Base installation intentionally excludes FastAPI, Uvicorn, httpx, and MCP dependencies.

## Claude plugin/content status

Status: **ready_with_limitations**. The Claude plugin/content bundle remains version `3.0.1`, independent of the Python package version `0.2.0`. The metadata describes authorized recon methodology and deterministic controls without claiming unrestricted autonomous exploitation.

## Skill catalog status

Status: **ready**. The shipped skill count is 11. The Python wheel includes a stable `outrider/skill_catalog.json` catalog and the runtime catalog accessor uses package resources when no repository root is explicitly supplied.

## MCP status

Status: **ready_with_limitations**. The MCP server remains optional and source-checkout based. It has five current tools, requires `run_dir` for network-capable tools, and uses fixed action-policy mapping before external activity.

## Web status

Status: **ready_with_limitations**. Static files are packaged in the wheel and loaded from `outrider/web_static`. Web dependencies are optional extras. The app is read-only and should not be reverse-proxied to a public interface without adding separate authentication and deployment controls.

## Packaging status

Status: **ready**. The package-data declaration includes `web_static/*`, `skill_catalog.json`, and `schemas/*.json`. The canonical runtime schema copies live under `outrider/schemas/` and are exposed through read-only importlib.resources accessors.

## Installer status

Status: **ready_with_limitations**. `install.sh` installs the 11 immediate skills and excludes `skills/_shared` as a separate skill. MCP and web dependencies are documented as separate optional installation steps.

## Security-control status

Status: **ready_with_limitations**. Deterministic controls cover scope, state, evidence, approvals, MCP boundary decisions, skill contract validation, and finding promotion. The repository audit uses deterministic local secret-like pattern checks; fixtures or examples that intentionally contain detector strings must remain documented as false positives.

## Documentation status

Status: **ready_with_limitations**. Public documentation now distinguishes skill methodology, deterministic Python controls, optional MCP enrichment, optional web review, and independent version domains.

## Test and CI status

Status: **ready_with_limitations**. Base-package compatibility is tested on Python 3.10, 3.11, and 3.12 without optional web dependencies. The optional web control-plane integration suite runs once on Python 3.12 with `.[web]` installed. A separate release-readiness package-build job builds distributions, runs the audit, checks package contents, and performs clean base/web installation smoke checks without live target network calls.

## Known limitations

- The Python package remains pre-1.0 at `0.2.0`; this does not claim stable post-1.0 API guarantees.
- The MCP server is a source-checkout companion, not a separately published wheel component.
- The web review plane has no authentication and is intended for loopback-only local review.
- Claude skill capabilities are methodology/content capabilities; they are not equivalent to autonomous execution in the Python CLI.

## Resolved blockers

- Installed-wheel skill catalog no longer depends on a Git checkout or `skills/*/SKILL.md` beside the installed package.
- Contract schemas are available from the installed wheel through package resources.
- Static web assets are included as package data and can be loaded in a clean web installation.
- CLI version discovery is available as `outrider --version` and reports the Python distribution version only.
- `python -m outrider` delegates to the CLI without duplicating parsing.
- CI includes package-build and clean-install validation.

## Unresolved blockers

None identified after this audit. Remaining items are release limitations, not blockers.

## Release recommendation

**historical recommendation completed:** the version/release preparation proceeded, and maintainers subsequently published the GitHub releases described in the post-release status above. Future release PRs should acknowledge current limitations and wait for all GitHub Actions jobs to pass.

## Historical version-domain recommendation (applied by release preparation)

- **Python package:** next change should be a **minor** version, recommended `0.2.0`, because packaging resources, CLI discoverability, and installed-wheel behavior are materially improved while preserving current semantics.
- **Claude plugin/content bundle:** next change should be a **patch** version, recommended `3.0.1`, because metadata/documentation truth is corrected without changing skill semantics or skill versions.
- **Individual skills:** **no version change** is recommended for this audit because skill content semantics are unchanged.
- **JSON schemas:** **no version change** is recommended because schema semantics remain version `1`.

## Historical applied version decision for release preparation

- Python package `0.2.0` was applied as a minor pre-1.0 release candidate for backward-compatible deterministic control-plane functionality during release preparation; it was subsequently published as the GitHub release noted above.
- Claude plugin/content `3.0.1` was applied as a patch release candidate for metadata and documentation truth corrections during release preparation; it was subsequently published as the GitHub release noted above.
- Individual skill frontmatter versions are unchanged.
- Manifest, state-event, evidence, approval, skill-request, skill-result, and finding schemas remain at version `1`.
- Deterministic candidate artifacts can be built locally or through the manual unsigned release-candidate workflow.
- At the time of the preparation PR, release tags and release records had not yet been created; maintainers later created the two GitHub release records described in the post-release status. PyPI publication and Claude Marketplace publication are still not claimed.
- Status remains **ready_with_limitations** because MCP is source-checkout based, the web plane is loopback-only and unauthenticated, and publication is manual.
