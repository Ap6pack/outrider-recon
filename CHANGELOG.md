# Changelog

All notable changes to these skills are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Added deterministic guided engagement progress and server-derived next actions.
- Added explicit beginner scope confirmation and guarded forward workflow actions.
- Added a governed agent-to-agent orchestrator loop (`outrider orchestrate run|status`) that advances a run by creating each hop through the existing request/result contract, re-evaluating scope, approval, and workflow state on every hop. It auto-dispatches only local and passive actions, requires a standing approval for active enumeration, treats intrusive and prohibited actions as handoff-only, is bounded and resumable, and never promotes findings. Skill execution is delegated to an injected executor; live execution is off by default. (ADR 0017)
- Added an independent advisory verifier (`outrider verify candidates`) that attempts to falsify each finding candidate against its cited evidence and current scope, recording `supported`, `refuted`, or `insufficient_evidence` verdicts under `contracts/verification/`. Verdicts never promote, never delete, and never gate promotion eligibility. (ADR 0018)
- Added a deterministic benchmark harness (`outrider benchmark run|analyze-misses`) that drives the loop over a synthetic ground-truth corpus with a stub executor and scores schema conformance, discovered-candidate precision/recall, and finding-candidate coverage. Metrics are reproducible with no model or network; a shipped corpus and the `ground-truth-v1` and `verification-v1` contracts back it. (ADR 0019)
- Added `tests/test_secret_scan.py`, pinning the secret-pattern catalog's exact-length contract in both directions.
- Added `bootstrap.sh`: one command that creates an isolated virtualenv, installs the package (web extra by default), links the Claude skills from the checkout, and runs the deterministic self-check. Flags: `--no-web`, `--no-skills`, `--help`.
- Added a `Dockerfile` (+ `.dockerignore`) that serves the loopback-only web portal; reachable on Linux with `docker run --network host`. It deliberately does not bind `0.0.0.0`. CI now builds the image and smoke-tests `/api/health`.
- Added portal UI for the runs↔targets bridge: a dashboard **Import Legacy Target** form (`POST /api/import-target`, sources listed by `GET /api/import/sources`) and a per-engagement **Materialize to targets/** button (`POST /api/runs/{run_id}/materialize`). Import is restricted to subfolders of a configured targets base (`bridge.resolve_import_source` rejects absolute paths, `..` traversal, and symlink escapes); the base defaults to a `targets/` folder beside the runs root and is overridable with `--targets-root`. Both endpoints use the existing control-token mutation guard, and `/api/health` now advertises `legacy_import` and `materialize` capabilities.
- Added a bridge between legacy `targets/` workspaces and the governed `runs/` plane (`outrider/bridge.py`). `outrider import-target <dir> --target … --actor … --authorization-reference …` creates a governed run and registers the legacy files as evidence under `artifacts/imported/` (hash + size; idempotent; `--dry-run` previews) — no notes are parsed and no findings are fabricated. `outrider materialize <run|run_id>` renders a read-only `targets/<name>/OUTRIDER-RUN.md` working view (scope, progress, registered evidence, promoted findings) and never overwrites the operator's own files (only its own generated file, guarded by a banner unless `--force`). Both operate solely on the gitignored `runs/` and `targets/` trees.

### Changed

- The portal's Import Legacy Target form now prefills to cut repeated typing: selecting a folder seeds the target field, the in-scope box auto-fills as `target` + `*.target` while untouched (mirroring the New Engagement wizard), and the operator name is remembered across imports in the same session. It reads only the folder name the operator picked — never the folder's contents — and the authorization reference and final scope stay manual. No browser storage is used.
- Packaged the benchmark ground-truth corpus and the new contract schemas so the loop and harness work from an installed wheel; the release-readiness smoke now exercises the new subcommands and runs the corpus offline.
- Replaced each skill's non-functional `triggers:` list with the supported `when_to_use` frontmatter field and dropped the ignored per-skill `version:`. Neither old field exists in the Agent Skills specification, so the authored trigger vocabulary never reached skill dispatch. Lint, release audit, and contributor docs now enforce the real contract.
- Merged the archiver pointers from the former evidence-preservation method file into `analysis-and-reporting` §8, and eight failure modes not already covered into `osint-methodology` §5.
- Pointed the README quick start at the one-click installer instead of `cp -r skills/*`, which contradicted the installation guide and produced installs that never received updates.
- Vendored the portal's Space Grotesk and IBM Plex Mono fonts locally under `/static/fonts` (weights 400 and 600, the only ones used) and removed the remote Google Fonts `@import`. The portal's strict CSP (`style-src 'self'`) had blocked the remote stylesheet, so the console theme's type never actually loaded and every page load logged a CSP violation; the fonts now load offline with no third-party request. Also removed dead header CSS left behind by the banner change.
- Extended the release audit with a `stylesheet asset locality` check that fails when `app.css` references a remote URL, and the clean web-wheel smoke now proves the vendored fonts ship and no remote font import remains — closing the gap that let the remote import pass CI.

### Fixed

- Restored the functional Advanced Workspace controls alongside web-first onboarding.
- Removed hard-coded next actions, corrected terminal phase labels, removed hidden static test markers, and corrected malformed architecture wording.
- Fixed an unhandled `re.error` crash in `h1_reference.py` when `--query` or `--cwe` received an invalid regular expression.
- Hardened `copy_repo_fixture` in the release-readiness tests to strip `runs/`, `.venv/`, and `venv/` (and added `.venv/`/`venv/` to `.gitignore`). Previously, running `outrider init` or the web portal created a local `runs/` folder that the fixture copied into a `.git`-less audit, tripping `check_artifacts` and failing `test_warning_and_failure_exit_codes` for anyone who had actually used the tool.
- Fixed the `secret_scan.py` CI smoke test, whose GitHub PAT fixture carried 37 characters instead of 36 and was never asserted on, so `GH_PAT_CLASSIC` silently never matched.
- Fixed `install.sh` copying helper scripts onto themselves through a symlink while silencing the resulting error, and counting unrelated skills already present in `~/.claude/skills`.
- Fixed `uninstall.sh` removing skills by hardcoded name, which could delete a user's own skill sharing a generic name; it now removes only symlinks resolving into the install directory.
- Corrected stale documentation counts and roadmap state: the Tier 3 smoke-test heading, the prompt totals, and the released-versus-upcoming status of v3.1.
- Restored the page's `<h1>` (visually hidden via `.sr-only`) that the new banner header had replaced with an image, fixing the document-outline and screen-reader regression.
- Raised the contrast of form field-hint text (`label small`) so it meets WCAG AA on the dark theme.
- Cleaned up the SVG brand banner: stripped an embedded ~7 KB C2PA provenance manifest (halving the file) and replaced fabricated security telemetry — invented finding counts, a "LIVE" indicator, and live agent-status dots — with a static capability list, so the masthead no longer displays fabricated findings in a tool whose findings are human-promoted.
- Restored five web portal helper functions (`labelInput`, `badge`, `records`, `card`, `postTransition`) that were dropped from `app.js` during the web-first rewrite. They were called 77 times but defined nowhere, so every engagement view threw `ReferenceError: labelInput is not defined` the moment it built a form — the "Review Scope" / "Continue" actions and every advanced-workspace panel were unusable. `node --check` only validates syntax, so the runtime break shipped unnoticed.
- Added a dependency-free Node runtime regression check (`tools/web_js_runtime_check.js`, run in CI and via `tests/test_web_js_runtime.py`) that loads `app.js` under a DOM stub and exercises the form render paths, so a called-but-undefined helper now fails CI instead of only breaking in the browser.
- Hardened `web_view.list_runs` so a single run whose overview or workflow-guide computation raises degrades to an error card instead of aborting the whole listing (which returned an empty dashboard for every engagement). The workflow guide is now built once per run rather than twice.

### Removed

- Removed `docs/methods/anti-patterns.md` and `docs/methods/evidence-preservation.md`. Both were unreferenced and largely duplicated skill content; their unique material was merged into the skills above.

---

## [Python 0.3.0] -- 2026-07-14

### Added

- Added deterministic complete web-control-plane acceptance coverage.
- Added guarded run creation, workflow-state transitions, initialized-only scope replacement, scope checks, approval controls, action-policy checks, evidence controls, contract controls, human finding promotion, and finding verification to the optional local web plane.
- Added fixed five-tool MCP catalog review, network-free preflight, and explicitly enabled transient invocation through the shared policy-gated enrichment module.
- Added isolated clean-install validation for base, web, enrichment, combined web/enrichment, MCP, full optional, and source-checkout MCP requirements installations.

### Changed

- Prepared the Python package as `0.3.0`, a minor pre-1.0 release for substantial backward-compatible expansion from read-only review into a guarded local control plane.
- Kept FastAPI, Uvicorn, HTTPX, MCP, and DNS-related dependencies out of the mandatory base install.
- Updated release-candidate workflow, deterministic bundle construction, package artifact names, release audit assumptions, and release-readiness assertions for Python 0.3.0.

### Fixed

- Removed the accidental forbidden HTTP client typo from optional dependency declarations and CI assertions.
- Reconciled current documentation and plugin metadata that still described the present web plane as read-only.

### Security

- Preserved loopback-only, unauthenticated, token-guarded mutation semantics and no-CORS/no-docs web defaults.
- Verified MCP enrichment remains disabled by default and creates no artifacts, evidence, contracts, findings, reports, jobs, or state events.

### Documentation

- Added Python 0.3.0 release notes with upgrade, artifact, checksum, optional-extra, and limitation guidance.
- Updated installation, usage, architecture, security, release-readiness, MCP, contract, and web-control-plane documentation for the completed implementation.

---

## [Claude plugin/content 3.1.0] -- 2026-07-14

### Changed

- Prepared the Claude plugin/content bundle as `3.1.0`; the bundle now includes Python 0.3.0 and the completed local control plane resources.
- Updated deterministic bundle metadata, artifact names, MCP implementation references, and current documentation.
- Corrected plugin metadata to describe 11 Claude-native skills, deterministic Python controls, the optional loopback-only limited-control web plane, human-reviewed finding promotion, optional fixed policy-gated MCP enrichment, and no autonomous recon orchestration.

### Documentation

- Added plugin/content 3.1.0 release notes.
- Preserved all 11 individual skill frontmatter versions and all schema versions.

---

## [3.0] -- 2026-05-29

### Added

- Claude Code plugin manifest (.claude-plugin/plugin.json) for marketplace discovery.
- One-click install script (install.sh) and uninstall script (uninstall.sh).
- Optional MCP server companion (mcp-server/) with 5 live API tools: crt.sh lookup, HudsonRock Cavalier, EPSS scoring, Wayback CDX, DNS records.
- .mcp.json configuration for automatic MCP server discovery.
- Tool-chaining recipes -- Recon-ng, SpiderFoot, Maltego module configs, bash-native multi-tool pipelines. (docs/methods/tool-chaining-recipes.md)
- OPSEC infrastructure as code -- Terraform VPS provisioning, SOCKS proxy stacks, HTTP redirectors, Axiom fleet, Ansible playbooks, teardown automation. (docs/methods/opsec-infrastructure.md)
- Adversary-emulation playbooks -- APT29, APT28, FIN7, Lazarus external recon emulation mapped to outrider-recon skills. (docs/reference/adversary-emulation.md)
- Sector-specific deep dives expanded -- HL7/FHIR endpoints, FIX protocol, ICS Shodan dorks, SAM.gov mining, firmware extraction. (docs/reference/specialty-domains.md)
- Report customization guide -- template variables, format adaptation, branding, pandoc delivery commands. (docs/methods/report-customization.md)
- Tool failure recovery -- fallback chains for subdomain discovery, port scanning, breach data, DNS/WHOIS, web probing. (docs/methods/tool-failure-recovery.md)

### Changed

- Capability count: 81 to 90 (9 new capabilities across tool integration and workflows).
- Coverage estimate: 90-95% to 95-98% for OSINT-phase work.

---

## [2.4] -- 2026-05-29

### Added

- Continuous monitoring playbook -- daily subdomain/DNS/cert diff pipeline, weekly deep scan orchestration, alert pipeline architecture (Slack/PagerDuty), false-positive tuning framework, baseline management, long-running engagement patterns. (docs/methods/continuous-monitoring.md)
- Multi-tenant engagement workflow -- directory convention, scope isolation with pre-flight check, credential/token segregation, output segregation, parallel execution patterns (GNU parallel, Axiom), reporting/delivery, engagement decommission. (docs/methods/multi-tenant-workflow.md)
- Burp Suite and ZAP setup recipes -- per-engagement config, 8+ recommended extensions, recon-specific proxy workflows, ZAP automation framework YAML, traffic tagging for bug bounty compliance, proxy chaining for OPSEC. (docs/methods/burp-zap-setup.md)

### Changed

- Capability count: 72 to 81 (9 new capabilities across monitoring, engagement ops, and proxy tooling).
- Coverage estimate: 85-90% to 90-95% for OSINT-phase work.

---

## [2.3] — 2026-05-29

### Architecture

- **Three-layer content separation.** Skill files (SKILL.md) now contain only agent-executable content — behavioral contracts, API endpoints, regex patterns, scoring rubrics, decision logic. Techniques and procedures moved to `docs/methods/`. Tool directories and reference material moved to `docs/reference/`.
- **Behavioral contracts added to all 11 skills.** Every SKILL.md now starts with a standardized contract: when triggered → execute steps → output format → severity rules → gating rules → chain to next skill.
- **Removed obsolete `scripts/sync-skill-content.sh`** — the two-tier content model (stubs + full-skills/) it supported was replaced by in-place SKILL.md files.

### Added

- **`docs/methods/`** — 5 files: copy-paste probes, CDN bypass techniques, active sweep scripts, anti-patterns, evidence preservation.
- **`docs/reference/`** — 3 files: consolidated tool directory, tooling install commands, specialty domain guides.
- **`web-surface`** — JS guess-paths (11 paths), endpoint extraction regex tiers (3 tiers), subdomain takeover provider fingerprints (27 providers), cloud bucket permutation arsenal (6 prefixes × 15 suffixes × 47 stems).
- **`recon-asset-discovery`** — Full 8-source crt.sh fallback chain (Censys, CertSpotter, CertStream, Subfinder, AlienVault OTX, ThreatMiner, URLScan, Anubis-DB). Wordlist sources table (7 sources with size guidance).
- **`identity-fabric`** — 5 SAML metadata probe paths. SSO subdomain prefixes expanded from 4 to 8. OIDC discovery directive on all alive subdomains.
- **`people-breach-intel`** — 5 additional package registries (RubyGems, Cargo, Packagist, NuGet, Maven Central). Mattermost/Rocket.Chat/self-hosted workspace discovery.
- **`analysis-and-reporting`** — Severity decision matrix expanded to 92 worked examples. Attack-path hint patterns expanded to 35 templates. Sector severity overrides table.
- **`docs/reference/tool-directory.md`** — 20+ tools added across categories: workspace discovery, vehicle/fleet intel, physical recon discipline, flight OSINT, cryptocurrency, threat intel, geospatial.
- **`docs/reference/tooling-install.md`** — 15 install commands added (assetfinder, dnsx, aquatone, feroxbuster, gospider, LinkFinder, cloud_enum, CloudSploit, o365enum, CredMaster, gf, hakrawler, reconftw, axiom, and more).
- **`docs/reference/specialty-domains.md`** — Expanded healthcare, finance, ICS/SCADA, government sections. Added IoT/consumer/SOHO and maritime/aviation/automotive.
- **`tests/smoke-test-prompts.md`** — Expanded from 32 to 43 prompts (40 functional + 3 scope-check bonus).
- **`web-surface` §9** — BIMI, MTA-STS, TLS-RPT, DNSSEC checks; DMARC reporting-vendor inference (8 vendors); MX-to-IdP/mail-host inference (6 providers).
- **`people-breach-intel` §4.1** — 9-signal vulnerability scoring rubric with P0–P3 priority tiers.
- **`analysis-and-reporting` §7–§9** — AI-assisted OSINT patterns, evidence preservation & archiving, automation & tooling quick-install.
- **`osint-methodology` §11** — Cert-SAN impersonation patterns; 5-vector phishing-readiness summary.
- **`recon-asset-discovery` §3** — Historical WHOIS and reverse WHOIS pivot techniques.
- **`cloud-and-infra` §3** — CircleCI added to CI/CD platform exposure table.
- **`web-surface` §14** — Legacy-extension Wayback pivot for brochure-ware sites.

### Fixed

- Corrected 6 wrong skill attributions in `docs/capabilities.md` (AWS account-ID, LinkedIn, KEV/EPSS, sat imagery, public records).
- Fixed 2 phantom capabilities (DMARC vendor inference, MX-to-IdP) by implementing the content.
- Fixed CHANGELOG dork count (80+ → 70).
- Fixed stale "Both skills" → "All skills" across README, smoke tests, and docs.
- Fixed offensive-osint router overpromises (removed geospatial, crypto, media claims).
- Added report-template (S9) to router dispatch table and architecture Mermaid diagram.
- Fixed roadmap version ordering in `docs/coverage.md`.
- Updated `CLAUDE.md.example` for router + sub-skill architecture.
- Removed duplicate OneLogin row in `identity-fabric` §1.5.
- Fixed ambiguous `scripts/` paths to `skills/offensive-osint/scripts/`.

### Changed

- **Skill line counts:**

| Skill                    | Before | After  |
| ------------------------ | ------ | ------ |
| `web-surface`            | 364    | 417    |
| `identity-fabric`        | 426    | 450    |
| `analysis-and-reporting` | 303    | 279    |
| `people-breach-intel`    | 313    | 247    |
| `recon-asset-discovery`  | 286    | 188    |
| `osint-methodology`      | 455    | 420    |
| Total (11 skills)        | ~3,224 | ~2,997 |
| `docs/methods/`          | —      | 380    |
| `docs/reference/`        | —      | 551    |
| **Grand total**          | ~3,224 | ~3,928 |

---

## [2.2.1] — 2026-05-24

### Changed

- **`osint-methodology` trimmed from 1,694 → 455 lines.** Retained full methodology core: confidence levels + upgrade workflows, 5-stage pipeline + time budgets, asset graph + triage rules, severity rubric, OpSec + detectability + back-off, breach × identity correlation, anti-patterns, bug-bounty submission, client deliverable templates. Removed duplicate implementation content now covered by the offensive-osint sub-skills.

### Added

- **7 remaining offensive-osint sub-skills** (all under 500 lines):
  - `recon-asset-discovery` (286 lines) — subdomains, ASN/BGP, CT logs, WHOIS/RDAP, DNS catalog, geospatial, regional search engines.
  - `web-surface` (364 lines) — Swagger/GraphQL probe paths, curl one-liners, vendor fingerprints, CDN bypass, Wayback CDX, Postman, endpoint scoring.
  - `secrets-and-dorks` (312 lines) — 48-pattern secret regex catalog, 70 dork corpus, GitHub code-search dorks, 9 read-only validators.
  - `post-discovery` (240 lines) — JWT triage, AWS IAM enum, GitHub/Slack post-credential workflows. Gated: requires validator confirmation first.
  - `cloud-and-infra` (236 lines) — cloud-native fingerprints, K8s/etcd/kubelet, CI/CD exposure, TLS deep audit.
  - `people-breach-intel` (313 lines) — HudsonRock, breach data, username/email/phone, people search, social media, crypto, media.
  - `analysis-and-reporting` (303 lines) — scoring rubrics, attack-path hints, severity decision matrix, sector-specific notes.
- **Updated README.md** — structure block and What is this? section updated to list all sub-skills.

---

## [2.2] — 2026-05-24

### Architecture

- **Refactored `offensive-osint` from monolith to router + sub-skills.** The 4,168-line single file has been replaced with a 62-line router (`skills/offensive-osint/SKILL.md`) that dispatches to focused sub-skills by task type. Each sub-skill is self-contained and under 500 lines, preventing context overload in long sessions.
- **Added `identity-fabric` sub-skill** (426 lines) — Entra, Okta, ADFS, SAML, M365 deep enum, GraphQL field-suggestion, LinkedIn employee enum.
- **Added `report-template` skill** — generic bug-bounty report scaffold.

### Setup

- **Added `CLAUDE.md.example`** — boilerplate Claude project config for users to copy and customise. Replaces the practice of committing engagement-specific `CLAUDE.md` files to the repo. Users run `cp CLAUDE.md.example CLAUDE.md` after cloning and fill in their own platform and handle.

### Added scripts

- **`skills/offensive-osint/scripts/h1_reference.py`** — stdlib-only Python script (no API key required) that queries HackerOne's public GraphQL API for disclosed reports. Supports top-voted/top-bounty sort, keyword search with cursor pagination, severity and CWE filters, program-specific lookups, JSON output.

### Repo hygiene

- **Updated `.gitignore`** — added: `findings/`, `mcp-proxy.jar`, `refreshSession.js`, `skills/hackerone/`, `.claude/settings.local.json`, `CLAUDE.md`. These are engagement artifacts and local config that must never be committed to a public repo.
- **Updated README.md** — structure block, tagline, What is this?, capability map, usage steps, and scripts section updated to reflect new architecture.
- **Updated CONTRIBUTING.md** — step 3 covers adding new sub-skills as peer directories; restored `CODE_OF_CONDUCT.md` link.

---

## [2.1] — 2026-04-27

Comprehensive expansion based on a 32-prompt smoke-test gap analysis. PASS rate moved from C-grade (1 PASS / 9 PARTIAL / 22 FAIL) to A-grade (31 PASS / 1 PARTIAL / 0 FAIL).

### `osint-methodology` — added 11 new sections / subsections

- **§2.1 Confidence Upgrade Workflows** — per-asset-type transition rules (subdomain, IP, webapp, email, bucket, endpoint, credential, person, repo, mobile app, certificate, SSO tenant).
- **§6.4 Detection-Aware Probing** — signs of detection (429s, captcha, WAF page, status drift, banner change, NXDOMAIN, honeypot bait, direct contact) + back-off ladder (slow down → switch endpoints → switch persona → switch IP → pause → consult).
- **§7.6 Time Budgeting & Engagement Profiles** — per-stage time estimates by org size; 1-hour rapid recon, 4-hour focused recon, 1-day standard, 1-week deep, ongoing weekly diff profiles.
- **§8.5 Asset-Level Triage Rules** — WebApp / Subdomain / IP / Email / Repo priority rubrics.
- **§10.1 Scale-Based Tactics** — small (<100), medium (100-1K), large (1K-10K), conglomerate (10K+) tactics.
- **§11.10 Microsoft 365 Deep Surface** — Teams Federation, SharePoint subdomains (-my, -admin), OneDrive personal-site enum, OAuth client_id discovery, device-code phishing target check, Power Platform.
- **§27 WAF / CDN Bypass & Origin Discovery** — DNS history pivot, cert SAN pivot, favicon hash + JARM origin clustering, direct IP probe with Host header, mail/ftp/cpanel exception, error page leakage, email-header bounce trick.
- **§28 Vulnerability Prioritization (CVE / EPSS / KEV)** — data sources + 9-signal rubric → priority tiers.
- **§29 Phishing Infrastructure & Pretext Development** — typosquat shortlists, subdomain takeover for trusted-domain phishing, email spoof feasibility matrix, pretext development from OSINT, per-role pretext templates, operational discipline.
- **§30 Bug Bounty Submission & Responsible Disclosure** — platform basics (HackerOne/Bugcrowd/Intigriti/YesWeHack/HackenProof/Open BB/security.txt), universal report structure, severity inference per program, CVD process, cloud provider disclosure channels.
- **§31 Client Deliverable Templates** — executive summary template, per-finding report card template, risk translation matrix (11+ technical findings → business-language impact), reporting cadence, reproduction package contents.

### `offensive-osint` — added 11 new §16 subsections + 7 new top-level sections + many expansions

#### New §16 subsections (Pre-built Wordlists & Probe Paths)

- **§16.13 Copy-Paste Probes** — curl one-liners for every check (15 always-on HTTP, 8 SSO prefixes, 5 SAML paths, S3/GCS/Azure HEAD+GET, GraphQL introspection POST, all 9 read-only validators, httpx bulk).
- **§16.14 Email Security Analysis** — SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC parsing + SaaS tenant inference table + 25+ TXT verification token patterns.
- **§16.15 Origin Discovery / CDN Bypass** — 8 techniques to find origin behind Cloudflare/Akamai/Fastly/CloudFront.
- **§16.16 Vendor Product Fingerprints** — Citrix Netscaler, F5 BIG-IP, Cisco ASA, Pulse Secure, FortiGate, PaloAlto GlobalProtect, VMware Horizon/vCenter/ESXi, Microsoft Exchange, WatchGuard, SonicWall, Sophos, Check Point, Zoho ManageEngine, Atlassian Confluence/Jira, GitLab self-hosted, Telerik UI, ConnectWise ScreenConnect, SolarWinds, Kaseya — with KEV CVE associations.
- **§16.17 Cloud-Native Service Fingerprints** — AWS Lambda Function URLs, App Runner, API Gateway, CloudFront, ALB; Google Cloud Run, Cloud Functions, App Engine; Azure Functions, Container Apps, Static Web Apps; Vercel, Netlify, Cloudflare Workers/Pages, Heroku, Render, Fly.io, Railway, DigitalOcean App Platform.
- **§16.18 Container & Kubernetes Exposure** — Docker API (2375/2376), Kubernetes API server (6443), kubelet (10250), etcd (2379), dashboard, kube-proxy/controller/scheduler, cAdvisor, Helm Tiller, Docker Hub / Quay / GHCR / ECR Public / GCR registry enum + per-image scan workflow.
- **§16.19 CI/CD Platform Exposure** — Jenkins (deeper), GitLab self-hosted, GitHub Actions secrets-in-workflow patterns, CircleCI, TeamCity (KEV CVE), Bamboo, Drone CI, Travis CI legacy, Argo CD, Tekton, Spinnaker, Buildkite.
- **§16.20 Documentation/Wiki Leak Paths** — Notion, Confluence Cloud, Atlassian Service Desk, Trello, Asana, ReadTheDocs, GitBook, MkDocs/Docusaurus, Slab, Coda, Miro, Lucidchart, Figma, GitHub Wiki, Linear, self-hosted Confluence, Monday.com, Wrike + dork-driven discovery.
- **§16.21 WHOIS / RDAP / Historical** — current WHOIS, RDAP (RFC 7480), historical WHOIS sources (DomainTools, WhoisXML, SecurityTrails, viewdns.info, whoisology.com), reverse-WHOIS pivots.
- **§16.22 DNS Record Catalog** — per-record-type rubric + TXT verification token table mapping ~25 patterns to SaaS tenants (Google Workspace, M365, Atlassian, Adobe, DocuSign, Dropbox, Box, Webex, Zoom, Notion, Slack EG, Asana, MongoDB Atlas, etc.) + CAA + SOA serial pattern analysis.
- **§16.23 Wayback CDX Deep Usage** — full CDX API filter parameters + diff workflow + bulk archived JS extraction.

#### Catalog & corpus expansions

- **§17 Secret-Pattern Catalog** expanded from 29 to **48 patterns**. Added: Anthropic API key (`sk-ant-`), OpenAI legacy + project keys, OpenAI session, HuggingFace (`hf_`), Cloudflare API key (typed + global), DigitalOcean (`dop_v1_`), npm (`npm_`), PyPI (`pypi-`), Docker Hub (`dckr_pat_`), Atlassian (`ATATT3xFfGF0_`), New Relic, DataDog (typed), Sentry DSN, ngrok, Linear, Discord bot token, Telegram bot token.
- **§18 Dork Corpus** expanded from 50+ to **70 templates** across **9 categories** (added: internal tool exposure, backup/dump file extensions, sector-specific for healthcare/finance/gov).

#### Identity & validators

- **§22.8 Microsoft 365 Deep Enumeration** — Teams federation API, SharePoint subdomain probe (3 patterns), OneDrive personal site enum, M365 OAuth client_id discovery, `device_authorization_endpoint` phishing-target check, Power Platform / Dynamics URLs.
- **§22.9 GraphQL Field-Suggestion Enumeration** — recipe + tooling (clairvoyance, graphql-cop, InQL) + alias batching + query-depth bypass + subscription enumeration + batched-query bypass.
- **§23 Read-Only Secret Validators** expanded from 4 to **9 providers**. Added: Anthropic API key, OpenAI API key, npm token, Atlassian API token, DataDog API+APP key.
- **§23.12 Post-Discovery Enumeration Workflows** — AWS IAM enum (sts → iam → simulate-principal-policy), GitHub PAT scope/repo enum, Slack workspace enum (auth.test → users.identity → conversations.list), JWT full triage (algorithm-confusion + brute-force + none-bypass), Postman PMAK workspace enum, Anthropic + OpenAI usage enum, generic key provenance enum.
- **§24 Postman Endpoint** pinned with verified shape (mid-2025+) + DevTools fallback recipe.

#### Audit / vulnerability / measurement

- **§27.1 Wordlist Sources** — Assetnote, SecLists, jhaddix all.txt, OneListForAll, raft-large-words, fuzzdb, PayloadsAllTheThings + size guidance + tooling examples.
- **§28.4 TLS Deep Audit** — sslyze + testssl.sh + nmap script alternatives + JA3/JA4 reference DBs + 14-row issue table.
- **§28.5 Reverse DNS Sweep + IPv6 Enum + BGP route observation** — within-scope sweep, IPv6 considerations, RouteViews / RIPE RIS, third-party PTR pivots.
- **§29.2 Vulnerability Prioritization Data Sources** — NVD, EPSS, CISA KEV, ExploitDB, Metasploit, InTheWild.io, OpenCVE, Trickest CVE→POC, GitHub Security Advisories, MITRE CVE, OSV.dev, VulnCheck KEV + bulk prioritization workflow.

#### Hints & severity

- **§39 Attack-Path Hint Patterns** expanded with **15 more templates** (open kubelet/etcd, K8s API anonymous, Citrix/F5/vCenter/Cloud Function unauth, npm typosquat, DMARC missing, live AI keys, Slack invite, sourcemap with sourcesContent, etc.).
- **§40 Severity Decision Matrix** expanded with **30 more worked examples** covering Kubernetes/container, vendor products with KEV CVEs, M365/cloud-native, CI/CD misconfig, documentation leaks, email-security gaps, AI/package-registry credentials, TLS issues.

#### New top-level sections

- **§41 LinkedIn Employee Enumeration** — search techniques (free + Sales Navigator), Google dork, tooling, role-tier prioritization (P0–P5), email-pattern derivation cross-reference, sock-puppet considerations, output schema.
- **§42 Job Posting Tech-Stack Analysis** — sources (LinkedIn Jobs / Indeed / Glassdoor / Lever / Greenhouse / Workable / AshbyHQ / AngelList / BuiltIn), what to extract, tooling, output schema.
- **§43 Slack / Discord / Telegram / Mattermost Workspace Discovery** — Slack invite-link enum, Discord server discovery, Telegram, Microsoft Teams federation, Mattermost / Rocket.Chat / self-hosted.
- **§44 Package Registry Leak Hunting** — npm + PyPI + RubyGems + Cargo + Packagist + NuGet + Maven Central + Docker Hub/Quay/GHCR + per-registry workflow + typosquat surveillance.
- **§45 Sat Imagery for Physical Recon** — sources, what to extract for physical recon, OSINT-derived intel beyond satellites (LinkedIn / Glassdoor / Instagram / press releases), vehicle/fleet intel, discipline.
- **§46 Tooling Quick-Install** — 35+ install one-liners across 12 categories.
- **§47 Sector-Specific Recon Notes** — healthcare (DICOM/HL7/FHIR/EHR), finance (SWIFT/FIX/Bloomberg/banking middleware), ICS/SCADA (Modbus/BACnet/S7/DNP3 + caution discipline), IoT (MQTT/CoAP/UPnP), government (FedRAMP/FISMA/USAspending), maritime/aviation/auto.

#### Renumbering

- §41 (Runnable Helper) → **§48**
- §42 (Skill Self-Test) → **§49** (refreshed with v2.1 prompts; expanded to 30 prompts)
- §43 (Changelog) → **§50** (this entry added)

### File-size delta

| File                         | v2.0        | v2.1            |
| ---------------------------- | ----------- | --------------- |
| `osint-methodology.SKILL.md` | 1,181 lines | **1,694 lines** |
| `offensive-osint.SKILL.md`   | 1,698 lines | **3,828 lines** |
| Combined                     | 2,879 lines | **5,522 lines** |

### Smoke-test re-grade

After v2.1: **31 PASS / 1 PARTIAL / 0 FAIL** out of 32 (was 1/9/22 in v2.0).

---

## [2.0] — 2026-04-27

Major rewrite for external red-team posture. Both skills tagged `version: 2.0`.

### `osint-methodology`

- Added: 5-stage recon pipeline (§7), asset-graph discipline with 29 asset types (§8), findings rubric with severity examples (§9), bug-bounty pivot modes (§10), identity-fabric mapping (§11), API & auth-map methodology (§12), JS deep analysis (§13), mobile attack surface (§14), cloud attack surface (§15), breach × identity correlation (§22), detectability tagging (§6.2), validator discipline (§6.3), cross-module coordination (§24.2), multi-engine corpus run methodology (§24.3), evidence preservation (§24.4), anti-patterns (§26).
- Strengthened: confidence levels (§2), output format (§3), source hygiene (§4), do-not rules (§5), authorization preamble (§1).
- Retained: original methodology content (OpSec, Crypto, Image/Video/Chrono, Threat Actor incl. RU/CN, Synthetic Media).

### `offensive-osint`

- Added: pre-built wordlists & probe paths (§16), 29-pattern secret catalog (§17), 50+ dork corpus (§18), GitHub code-search dorks (§19), endpoint interest score 0-100 rubric (§20), mobile ownership confidence (§21), identity-fabric concrete endpoints (§22), 4 read-only secret validators (§23), Postman workspace search (§24), Stack Exchange sweep (§25), public SaaS dorks (§26), subdomain-source stack (§27), domain-level breach severity (§15.1), L2 explorer table (§30.2), USCC + ICP workflow (§14.2), cross-module sidecar coordination (§36), attack-path hint patterns (§39), severity decision matrix (§40), runnable secret-scan helper (§41).
- Retained: original tool tables (search engines, username/email, people, phone, social, public records, breach, infrastructure, threat intel, crypto, media, geospatial, AI, archiving, automation, regional, telegram).

---

## [1.x] — pre-2026

- `osint-methodology`: original framework based on [SnailSploit/offensive-checklist](https://github.com/SnailSploit/offensive-checklist).
- `offensive-osint`: original tool-reference cheat sheet.

### Attribution

This project is a fork of [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT).

## Historical Unreleased Notes

### Added

- Added a web-first `outrider` launcher that safely starts the loopback portal and opens the local browser.
- Added beginner engagement onboarding with guided authorization, platform, scope, traffic-identification metadata, review, creation, and resume flows.

- Added append-only `findings.jsonl` validated-finding records with human-reviewed promotion from evidence-backed `finding_candidate` claims, source-result/source-claim provenance, source-result SHA-256 recording, evidence-integrity enforcement, current-scope and workflow-state checks, and finding list/show/verify CLI commands without automatic execution or automatic promotion.

- Added versioned skill request/result contracts, a deterministic shipped-skill catalog, policy-aware request creation and validation, evidence-backed result validation with candidate/action assessments, and shared contract instructions for all shipped skills without adding skill execution or finding promotion.

- Added existing-artifact evidence registration and evidence integrity verification in the local web control plane without artifact upload or download.
- Added guarded browser creation of policy-checked `skill_request` v1 contracts without executing skills.
- Added point-in-time browser validation of existing request and result contracts, including evidence, linked-request, scope, and recommended-action assessments.

### Changed

- Made the browser onboarding experience the primary human entry point while retaining CLI subcommands for advanced and automated use.
