![outrider-recon banner](assets/outrider-recon-banner.svg)

# outrider-recon

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-11-green.svg)](#structure)
[![Capabilities](https://img.shields.io/badge/capabilities-90-orange.svg)](docs/capabilities.md)
[![Claude Code](https://img.shields.io/badge/Claude_Code-plugin-8A05FF.svg)](#quick-start)
[![MCP Server](https://img.shields.io/badge/MCP-5_tools-dc2626.svg)](mcp-server/)

> **Claude-native external recon and ASM for bug bounty, pentest, and security teams.** Outrider maps assets, identity fabric, exposed web/API surface, cloud and SaaS exposure, secrets, and public bug-bounty intelligence into ranked attack paths and evidence-backed recon findings.

Outrider is not another subdomain-enum wrapper. It is an agentic recon workflow that helps answer the question most recon output leaves open:

> **What matters first, and why?**

---

## Version domains and installation boundaries

Outrider uses independent version domains. The Python package remains `0.2.0`; the Claude plugin/content bundle remains `3.0.1`; each skill keeps its own frontmatter version; and JSON contract schemas currently use schema version `1`. Do not assume the Python package version and Claude plugin/content version move together.

The base Python package installs the deterministic local controls and CLI with PyYAML only. Web review support is optional via the `web` extra, and MCP server dependencies are installed separately from `mcp-server/requirements.txt` in a source checkout.

## Current repository release candidates

Prepared release versions in this repository are Python package release candidate: 0.2.0 and Claude plugin/content release candidate: 3.0.1. Individual skill versions remain independent, and JSON schema versions remain at `1`. These candidates are not published releases until maintainers create tags, GitHub release records, and any optional PyPI publication.

Release-readiness commands:

```bash
python tools/release_audit.py
python tools/build_release_bundle.py --output-dir dist --source-date-epoch 1783900800
```

The manual `release-candidate.yml` workflow can be triggered through GitHub Actions `workflow_dispatch` to build unsigned candidate artifacts. Publication remains a maintainer action.

## Optional MCP policy enforcement

The optional MCP server exposes five bounded enrichment tools and now requires an explicit Outrider `run_dir` for every call. Before any HTTP request or DNS resolution, each MCP tool evaluates the current run manifest, workflow state, scope, and approval policy through the existing Python control layer.

Passive public-source lookups require current scope and a workflow state that permits `public_source_lookup`. `dns_records` additionally requires an active exact matching `target_enumeration` approval for the normalized domain. MCP discoveries are observations only: they do not expand `scope.yaml`, do not automatically register evidence, and do not modify run-control files. No MCP tool executes intrusive or prohibited actions.

## Why Outrider exists

Most recon tooling tells you what exists: subdomains, ports, URLs, technologies, leaked files, and maybe a few nuclei hits.

That is useful, but it is not enough. Operators still have to decide:

- Which assets are worth testing first?
- Which identity, cloud, API, or secret signals change priority?
- What public bug-bounty techniques worked against similar surfaces?
- What is safe to validate now, and what should be handed off to active testing?
- What evidence is good enough to brief a client or triage team?

Outrider is built for that middle layer between raw recon and active exploitation: **external recon → attack-path intelligence → safe handoff**.

---

## What it does

Use Outrider to:

- Map an organization's external attack surface.
- Discover web/API, identity, cloud, SaaS, secrets, and people/breach signals.
- Compare discovered surfaces against public bug-bounty disclosure patterns.
- Score assets and findings by confidence, severity, detectability, and attack-path value.
- Produce finding cards, report-ready evidence, and recommended handoffs.
- Stay inside an authorized, read-only recon boundary until the operator chooses the next step.

The current bundle includes **11 implemented Claude skills**, **90 capabilities**, **48 secret patterns**, **70 dorks**, **9 read-only validator procedures**, **35 attack-path templates**, and an optional MCP server for live enrichment. The skills are the implemented capability layer; deterministic Python enforcement now covers run manifests, workflow state, scope, approvals, evidence integrity, and MCP tool-boundary policy for the existing enrichment tools.

---

## End-to-end workflow

```text
Scope → Recon → Enrich → Bug Bounty Intel → Score → Finding Cards → Handoff → Report
```

| Phase                | What Outrider does                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Scope**            | Establish authorized assets, exclusions, platform rules, and safe boundaries.                                                                     |
| **Recon**            | Discover subdomains, DNS records, web apps, APIs, JS endpoints, Swagger/OpenAPI, GraphQL, buckets, vendor surfaces, and exposed docs.             |
| **Enrich**           | Add identity-fabric, breach, cloud, SaaS, CI/CD, package-registry, EPSS/KEV, and technology context.                                              |
| **Bug Bounty Intel** | Search public disclosed reports and writeups for comparable attack patterns, severity framing, and likely next probes.                            |
| **Score**            | Rank surfaces using confidence, severity, detectability, and attack-path value.                                                                   |
| **Finding Cards**    | Convert interesting signals into evidence-backed cards with confidence, impact, safe next steps, and handoff recommendations.                     |
| **Handoff**          | Recommend where to continue: proxy-assisted testing, manual validation, ASM ticketing, client remediation, or a separate active-testing workflow. |
| **Report**           | Produce recon/ASM summaries, bug-bounty report scaffolds, and executive-ready notes.                                                              |

---

## Disclosed Report Intelligence

Outrider includes a public bug-bounty intelligence layer. It can query HackerOne Hacktivity public disclosures and use prior real-world reports as technique references during recon.

The included `h1_reference.py` helper supports:

- top-voted reports for community-validated techniques,
- top-bounty reports for business-impact framing,
- keyword searches such as `SSRF`, `OAuth bypass`, `GraphQL IDOR`, or `open redirect`,
- client-side severity and CWE filtering,
- program-specific disclosure lookup,
- JSON output for downstream tooling.

This is not exploit automation. The intent is to answer:

> **What has worked against similar assets before, and what should I safely investigate first?**

Example use cases:

```bash
python3 skills/offensive-osint/scripts/h1_reference.py --top-voted --query "GraphQL" --pages 5
python3 skills/offensive-osint/scripts/h1_reference.py --top-bounty --query "OAuth bypass" --severity high critical --pages 3
python3 skills/offensive-osint/scripts/h1_reference.py --program gitlab --pages 5 --json
```

A future harness will promote this into a first-class `outrider intel` command that generates structured technique cards and stores them in the recon manifest.

---

## Example output

A good recon workflow should not end with a flat list of hosts. Outrider aims to produce ranked, evidence-backed leads like this:

```text
[HIGH] api.acme.example exposes OpenAPI schema
Confidence: Confirmed
Evidence: GET /openapi.json returned 200; schema includes user/account/order paths
Why it matters: API schema reveals object identifiers and hidden write endpoints
Public report intelligence: similar disclosed reports map to IDOR, mass assignment, and broken authorization patterns
Recommended handoff: hunt-api-misconfig, hunt-idor, Burp Repeater authorization testing
Safe next step: verify auth requirements and object-level authorization without modifying production data
```

See [`examples/05-sample-output.md`](examples/05-sample-output.md) for a fuller sanitized example.

---

## Who this is for

Outrider is useful for:

- bug-bounty hunters who want better target prioritization before active testing,
- pentesters doing external recon before web/API testing,
- ASM and vulnerability management teams that need to turn exposure into ranked action,
- red teams mapping initial-access surface without crossing into exploitation,
- security engineers evaluating identity, cloud, SaaS, and public-code exposure,
- researchers building Claude-native or MCP-assisted security workflows.

It is **not** intended for unauthorized testing, malware, credential abuse, persistence, evasion, internal post-exploitation, or destructive validation.

---

## Where Outrider fits

Outrider is designed to sit between raw discovery tools and active testing. It does not try to replace your scanner, proxy, ASM platform, ticketing system, or manual methodology. It makes the recon layer more useful by turning scattered signals into prioritized, evidence-backed leads.

Recommended flow:

```text
Outrider Recon → ranked leads / technique cards → proxy-assisted testing, manual validation, ASM tickets, or client remediation
```

The point is simple: Outrider finds what matters, explains why it matters, preserves the evidence, and gives the operator a safe next step.

---

## Quick Start

### One-Click Install

```bash
curl -fsSL https://raw.githubusercontent.com/Ap6pack/outrider-recon/main/install.sh | bash
```

This clones the repo, symlinks all 11 skills into `~/.claude/skills/`, and prepares Claude Code to auto-load the relevant skills. Re-run the same command to update.

### Offline scope checks

Run folders contain a `scope.yaml` file that can be evaluated without DNS resolution, hostname resolution, or network activity:

```bash
outrider scope-check runs/example.com api.example.com
outrider scope-check runs/example.com https://api.example.com/path --json
```

Scope rules are deterministic:

- exact domains such as `example.com` match only that exact domain and do not include subdomains;
- wildcard subdomains such as `*.example.com` match `api.example.com` and deeper subdomains, but do not include the apex `example.com`;
- exact IPv4/IPv6 addresses and IPv4/IPv6 CIDR networks are supported;
- `out_of_scope` exclusions override `in_scope` inclusions;
- unmatched candidates are denied by default;
- domain rules never authorize the IP addresses that a domain may resolve to because no DNS resolution occurs;
- `outrider scope-check` only parses local scope configuration and candidate values, and performs no network activity.

### Run manifests and workflow state

Initialize a run with a stable manifest and optional opaque authorization reference:

```bash
outrider init example.com \
  --actor authorized-operator \
  --authorization-reference EXAMPLE-ROE-001
```

Show and move local workflow state without network activity:

```bash
outrider state show runs/example.com
outrider state transition runs/example.com scoped \
  --actor authorized-operator
outrider state transition runs/example.com collecting \
  --actor authorized-operator
```

`manifest.json` contains stable run identity, including a UUID run ID. `run.jsonl` is the append-only source of workflow state; current state is derived from validated events rather than stored as mutable manifest data. Actor attribution is required for state transitions. Scope must validate before entering `scoped`. State transitions do not grant authorization, and `authorization_reference` is only an opaque metadata reference, not an approval record. Run folders and engagement data must not be committed. These state commands operate only on local files and perform no network activity.

### MCP Server (optional)

The optional MCP server adds live enrichment tools: crt.sh lookup, HudsonRock query, EPSS scoring, Wayback CDX, and DNS records.

```bash
pip install -r ~/.local/share/outrider-recon/mcp-server/requirements.txt
```

The `.mcp.json` config is included in the repo. All skills work without the MCP server; MCP just adds live data enrichment. The current MCP server enforces explicit `run_dir`, fixed action mappings, current scope, workflow state, and exact approval checks before any HTTP or DNS activity.

### Manual Claude Code install

```bash
# 1. Clone and install skills
git clone https://github.com/Ap6pack/outrider-recon.git
mkdir -p ~/.claude/skills
cp -r outrider-recon/skills/* ~/.claude/skills/

# 2. Set up your local Claude config
cp outrider-recon/CLAUDE.md.example outrider-recon/CLAUDE.md
# Edit CLAUDE.md — fill in your platform and handle for traffic tagging
```

Then in any Claude Code session, ask an external recon question. Skills auto-load based on the task.

### Single skill / manual use

```bash
cat skills/offensive-osint/SKILL.md | claude --system-file -
```

You can also paste any `SKILL.md` into a Claude Project, Claude API prompt, or another Agent Skills-compatible harness. All files are plain Markdown and can be used as operator checklists without Claude.

---

## Structure

```text
outrider-recon/
├── skills/
│   ├── osint-methodology/SKILL.md      # how to think: pipeline, asset graph, confidence, severity, deliverables
│   ├── offensive-osint/SKILL.md        # router: dispatches to sub-skills below
│   ├── recon-asset-discovery/SKILL.md  # subdomains, ASN, CT, DNS, WHOIS, wordlists
│   ├── web-surface/SKILL.md            # probe paths, takeover, buckets, Wayback, Postman, endpoint extraction
│   ├── identity-fabric/SKILL.md        # Entra, Okta, ADFS, SAML, M365, LinkedIn
│   ├── secrets-and-dorks/SKILL.md      # 48 regexes, 70 dorks, 9 validators
│   ├── post-discovery/SKILL.md         # JWT, AWS IAM, GitHub, Slack workflows
│   ├── cloud-and-infra/SKILL.md        # cloud-native, K8s, CI/CD, TLS
│   ├── people-breach-intel/SKILL.md    # breach, HudsonRock, email, package registries
│   ├── analysis-and-reporting/SKILL.md # scoring, severity matrix, attack-path hints, sector overrides
│   └── report-template/SKILL.md        # bug-bounty and client report scaffold
├── skills/offensive-osint/scripts/
│   ├── h1_reference.py                 # HackerOne disclosed-reports reference agent, no API key
│   └── secret_scan.py                  # stdlib-only secret scanner, JSONL output
├── mcp-server/                         # optional live enrichment tools; no scope enforcement yet
├── outrider/                           # Python CLI run-folder scaffolding
├── docs/                               # architecture, coverage, install, methods, reference docs
├── examples/                           # end-to-end walkthroughs and sample output
├── tests/smoke-test-prompts.md         # 43-prompt self-evaluation
├── CLAUDE.md.example                   # copy to CLAUDE.md and customize for your engagement
└── assets/outrider-recon-banner.svg
```

---

## Documentation

| Doc                                                          | Contents                                                                                                  |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| [`docs/capabilities.md`](docs/capabilities.md)               | Full capability index: 90 capabilities across 15 domains.                                                 |
| [`docs/architecture.md`](docs/architecture.md)               | Design philosophy, asset graph, confidence/severity/detectability models, sidecar coordination.           |
| [`docs/coverage.md`](docs/coverage.md)                       | Practitioner-coverage breakdown by archetype and engagement phase.                                        |
| [`docs/installation.md`](docs/installation.md)               | Symlink installs and multi-environment install patterns.                                                  |
| [`docs/usage.md`](docs/usage.md)                             | Trigger phrases and prompt templates.                                                                     |
| [`docs/methods/`](docs/methods/)                             | Techniques and procedures: probes, CDN bypass, sweeps, monitoring, multi-tenant workflow, Burp/ZAP setup. |
| [`docs/reference/`](docs/reference/)                         | Tool directory, install commands, and specialty domain guides.                                            |
| [`examples/`](examples/)                                     | Engagement walkthroughs and sanitized sample outputs.                                                     |
| [`tests/smoke-test-prompts.md`](tests/smoke-test-prompts.md) | 43-prompt self-evaluation suite.                                                                          |

---

## Implementation status

Outrider currently has four separate implementation domains:

- **Implemented Claude skill layer:** the `skills/` directory is the primary capability layer. The skills provide methodology, routing, recon procedures, scoring guidance, report templates, and operator-facing safety rules.
- **Python CLI scaffolding:** the `outrider` command currently initializes and inspects run folders. It creates files such as `scope.yaml`, `run.jsonl`, placeholder JSON sidecars, finding cards, technique cards, and report templates. It does not execute recon; it includes offline deterministic scope-file validation, durable state, evidence hash verification, approval records, and action-policy checks.
- **Optional MCP enrichment:** the MCP server provides policy-gated live enrichment tools for crt.sh, HudsonRock, EPSS, Wayback CDX, and DNS lookups. Every lookup requires an explicit run context and an allow decision before network or DNS activity.
- **Future web UI:** a web UI is intended as a shared control and review plane for scope, approvals, evidence, triage, and handoff. It is not implemented in this repository today.

## Roadmap

Existing scaffolding:

- `outrider init` creates a run folder, `scope.yaml`, `run.jsonl`, placeholder JSON files, finding cards, technique cards, surface notes, and a report scaffold.
- `outrider show` checks whether expected run-folder files exist.

Planned deterministic controls and productization work:

- machine-readable recon manifest and schema validation,
- deterministic scope checks at CLI and MCP tool boundaries,
- explicit approval records for higher-risk or post-discovery actions,
- evidence artifact registration and hash verification,
- first-class `outrider intel` for public disclosure intelligence,
- report export for external recon / ASM / bug-bounty workflows,
- handoff export for proxy-assisted testing, manual validation, ASM ticketing, and remediation workflows,
- delta mode for continuous exposure monitoring,
- future web UI for shared control and review.

The goal is not to turn Outrider into an exploitation framework. The goal is to make it the best Claude-native harness for **authorized external recon and attack-path prioritization**.

---

## Authorization

These skills are intended for assets you **own** or have **written authorization to assess**: red-team rules of engagement, bug-bounty in-scope assets, ASM contracts, or internal security assessments.

All skills include a soft scope check when you ask Claude to act against an unverified third-party target. These controls are currently skill-level and operator-enforced; deterministic Python scope checks are available through `outrider scope-check`, and MCP scope/state/approval enforcement is implemented for the optional enrichment tools. The skills explicitly exclude active exploitation, post-exploitation, malware development, persistence, evasion, and other activities beyond OSINT-driven reconnaissance. See [`SECURITY.md`](SECURITY.md) for the full posture.

---

## About

Operational tradecraft accumulated across external attack-surface engagements, codified into Claude skills. Engagement-platform agnostic: slot into any ASM, ticketing, asset-graph, bug-bounty, or pentest workflow you already use.

**Author:** [Ap6pack](https://github.com/Ap6pack)

**Forked from:** [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT)

**Original framework:** [SnailSploit/offensive-checklist](https://github.com/SnailSploit/offensive-checklist) (v1.x)

**Inspired by:** [Bellingcat's Online Investigations Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) · [IntelTechniques](https://inteltechniques.com/tools/) · [OSINT Framework](https://osintframework.com/)

**Tool inventory:** [ProjectDiscovery](https://github.com/projectdiscovery) · [Six2dez reconftw](https://github.com/six2dez/reconftw) · [SecLists](https://github.com/danielmiessler/SecLists) · [Assetnote Wordlists](https://wordlists.assetnote.io/)

**License:** [MIT](LICENSE) — use freely, attribution appreciated.

---

> _Raw recon tells you what exists. Outrider helps decide what matters first._

## Evidence registry and artifact verification

Outrider run folders include an append-only `evidence.jsonl` registry and an `artifacts/` directory for local evidence files. Artifact contents remain under `artifacts/`; the registry stores only metadata, provenance, relative paths, sizes, and SHA-256 hashes.

```bash
mkdir -p runs/example.com/artifacts/http

printf 'HTTP/1.1 200 OK\n' \
  > runs/example.com/artifacts/http/homepage-response.txt

outrider evidence register \
  runs/example.com \
  artifacts/http/homepage-response.txt \
  --actor authorized-operator \
  --type http-response \
  --media-type text/plain \
  --source manual-capture

outrider evidence list runs/example.com

outrider evidence verify runs/example.com
```

Evidence files must be beneath `artifacts/`. Absolute paths, traversal, symlinks, symlinked parent directories, directories, missing files, and Outrider control files are rejected. Duplicate paths are rejected; save updated artifacts under a new filename and register the new path. Registration does not grant authorization or approval, does not perform scope checks, and does not change run state. Verification is deterministic local file I/O, performs no network activity, and does not modify the registry or artifacts.

Run folders and evidence artifacts must never be committed.

## Offline approval records and action checks

Outrider run folders include an append-only `approvals.jsonl` registry for explicit, time-bounded operator approvals. Approval records are exact-candidate and action-specific: an approval for `example.com` does not approve `api.example.com`, and an approval for `target_read_only_request` does not approve `target_enumeration`. The command examples below show granting, checking, listing, and revoking an approval.

```bash
outrider approval grant \
  runs/example.com \
  target_read_only_request \
  api.example.com \
  --actor authorized-operator \
  --reason "Approved bounded read-only review" \
  --duration-minutes 60 \
  --conditions "No authentication attempts"

outrider action-check runs/example.com target_read_only_request --candidate api.example.com
outrider approval list runs/example.com
outrider approval revoke runs/example.com APPROVAL_UUID --actor authorized-operator --reason "Approval withdrawn"
```

Approvals expire and can be revoked by appending revocation records; grant records are not edited or deleted. Scope always overrides approval, so a current scope-file change can deny an otherwise approved candidate. Workflow state can also deny an otherwise approved action. Prohibited action categories such as credential abuse, destructive validation, persistence, malware, evasion, and uncontrolled exploitation cannot be approved.

The `actor` value is an operator-provided attribution string only. It is not authenticated identity, a digital signature, proof of written authorization, a substitute for `authorization_reference`, or a replacement for client rules of engagement. `outrider action-check` is an offline decision helper only: it executes no target action and performs no network activity. Run folders, including approval records, are local operational data and must not be committed.

## Structured skill interchange contracts

Outrider runs now include a local contract layout for versioned skill/Python interchange:

```text
contracts/
  requests/
  results/
```

Claude skills provide reasoning, methodology, routing, prioritization, and reporting guidance. Python remains the deterministic authority for run identity, workflow state, scope, approval policy, evidence integrity, and durable artifacts. Contract files are task context only: they are not permanent authorization, authenticated actor proof, scope expansion, approval records, evidence records, or validated findings.

Create a request without executing a skill:

```bash
outrider contract request create \
  runs/example.com \
  recon-asset-discovery \
  --actor authorized-operator \
  --objective "Identify authorized external assets related to example.com" \
  --action-type public_source_lookup \
  --candidate example.com
```

Validate a request with current scope, state, approval, and evidence controls:

```bash
outrider contract request validate \
  runs/example.com \
  runs/example.com/contracts/requests/REQUEST_UUID.json
```

Validate a skill result and its evidence-backed claims:

```bash
outrider contract result validate \
  runs/example.com \
  runs/example.com/contracts/results/RESULT_UUID.json
```

Skill results must cite registered evidence IDs for claims rather than raw paths. Discovered candidates are observations only and do not expand `scope.yaml`. The `finding_candidate` classification is not a validated finding and is not promoted by these commands. The contract commands do not execute Claude skills, invoke MCP automatically, perform network activity, capture evidence automatically, or promote findings.

## Deterministic finding promotion

Outrider keeps skill-produced candidates separate from human-reviewed findings. Skills may emit `finding_candidate` claims in validated skill-result contracts, but only the Python control layer can append a `validated_finding` to `findings.jsonl`. Promotion requires a human reviewer to provide attribution, title, affected candidate, severity, confidence, validation basis, validation reason, impact, and remediation. Suggested severity and confidence in the source claim are advisory only.

`findings.jsonl` is the append-only deterministic source of promoted findings. `findings.md` remains an operator-managed working document; automatic Markdown rendering is deferred. Promotion hashes the complete source result file with SHA-256, stores the source-result path and source-claim snapshot, verifies every referenced evidence artifact, requires the affected candidate to be currently in scope, and is allowed only during `analyzing` or `reporting`. The reviewer attribution string is not authenticated identity, and promotion performs no target action, HTTP request, DNS lookup, MCP invocation, approval grant, or automatic validation traffic.

Example promotion:

```sh
outrider finding promote \
  runs/example.com \
  runs/example.com/contracts/results/RESULT_UUID.json \
  CLAIM_UUID \
  --actor authorized-operator \
  --title "Public OpenAPI schema exposes internal API structure" \
  --candidate api.example.com \
  --location /openapi.json \
  --severity medium \
  --confidence high \
  --validation-basis response_evidence \
  --validation-reason "The registered response contains a valid OpenAPI schema." \
  --impact "The schema exposes undocumented routes and object structures." \
  --remediation "Restrict schema access and remove unnecessary production documentation."
```

List and verify promoted findings:

```sh
outrider finding list runs/example.com
outrider finding verify runs/example.com
```

## Local web review plane

Outrider includes an optional first-increment local web review plane for operator review of existing run folders. Install the optional web dependencies only when you want to use it:

```bash
python -m pip install -e ".[web]"
outrider web serve ./runs
```

Then open `http://127.0.0.1:8765`.

The web plane is loopback-only and accepts only `127.0.0.1`, `localhost`, or `::1` as bind hosts. It is read-only: browser-based run mutations are not implemented, artifact downloads are not served, and the interface does not execute skills, recon, network lookups, DNS, MCP calls, approvals, evidence registration, finding promotion, scope edits, or state transitions. It has no authentication, is not a multiuser server, and must not be placed behind a public reverse proxy. The dashboard and detail workspace show run identity, workflow state, scope, evidence integrity, approval status, skill contracts, promoted findings, warnings, and integrity errors. Command-line controls remain authoritative.
