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

The current bundle includes **11 implemented Claude skills**, **90 capabilities**, **48 secret patterns**, **70 dorks**, **9 read-only validator procedures**, **35 attack-path templates**, and an optional MCP server for live enrichment. The skills are the implemented capability layer; deterministic Python enforcement for scope, approvals, schemas, and evidence verification is planned but not yet implemented.

---

## End-to-end workflow

```text
Scope → Recon → Enrich → Bug Bounty Intel → Score → Finding Cards → Handoff → Report
```

| Phase | What Outrider does |
|---|---|
| **Scope** | Establish authorized assets, exclusions, platform rules, and safe boundaries. |
| **Recon** | Discover subdomains, DNS records, web apps, APIs, JS endpoints, Swagger/OpenAPI, GraphQL, buckets, vendor surfaces, and exposed docs. |
| **Enrich** | Add identity-fabric, breach, cloud, SaaS, CI/CD, package-registry, EPSS/KEV, and technology context. |
| **Bug Bounty Intel** | Search public disclosed reports and writeups for comparable attack patterns, severity framing, and likely next probes. |
| **Score** | Rank surfaces using confidence, severity, detectability, and attack-path value. |
| **Finding Cards** | Convert interesting signals into evidence-backed cards with confidence, impact, safe next steps, and handoff recommendations. |
| **Handoff** | Recommend where to continue: proxy-assisted testing, manual validation, ASM ticketing, client remediation, or a separate active-testing workflow. |
| **Report** | Produce recon/ASM summaries, bug-bounty report scaffolds, and executive-ready notes. |

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

### MCP Server (optional)

The optional MCP server adds live enrichment tools: crt.sh lookup, HudsonRock query, EPSS scoring, Wayback CDX, and DNS records.

```bash
pip install -r ~/.local/share/outrider-recon/mcp-server/requirements.txt
```

The `.mcp.json` config is included in the repo. All skills work without the MCP server; MCP just adds live data enrichment. The current MCP server does **not** enforce scope by itself, so operators must apply the same authorization boundary before invoking live lookups.

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

| Doc | Contents |
|---|---|
| [`docs/capabilities.md`](docs/capabilities.md) | Full capability index: 90 capabilities across 15 domains. |
| [`docs/architecture.md`](docs/architecture.md) | Design philosophy, asset graph, confidence/severity/detectability models, sidecar coordination. |
| [`docs/coverage.md`](docs/coverage.md) | Practitioner-coverage breakdown by archetype and engagement phase. |
| [`docs/installation.md`](docs/installation.md) | Symlink installs and multi-environment install patterns. |
| [`docs/usage.md`](docs/usage.md) | Trigger phrases and prompt templates. |
| [`docs/methods/`](docs/methods/) | Techniques and procedures: probes, CDN bypass, sweeps, monitoring, multi-tenant workflow, Burp/ZAP setup. |
| [`docs/reference/`](docs/reference/) | Tool directory, install commands, and specialty domain guides. |
| [`examples/`](examples/) | Engagement walkthroughs and sanitized sample outputs. |
| [`tests/smoke-test-prompts.md`](tests/smoke-test-prompts.md) | 43-prompt self-evaluation suite. |

---

## Implementation status

Outrider currently has four separate implementation domains:

- **Implemented Claude skill layer:** the `skills/` directory is the primary capability layer. The skills provide methodology, routing, recon procedures, scoring guidance, report templates, and operator-facing safety rules.
- **Python CLI scaffolding:** the `outrider` command currently initializes and inspects run folders. It creates files such as `scope.yaml`, `run.jsonl`, placeholder JSON sidecars, finding cards, technique cards, and report templates. It does not currently execute recon, validate schemas, enforce scope, record approvals, or verify evidence hashes.
- **Optional MCP enrichment:** the MCP server provides live enrichment tools for crt.sh, HudsonRock, EPSS, Wayback CDX, and DNS lookups. It does not currently enforce scope at the tool boundary.
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

All skills include a soft scope check when you ask Claude to act against an unverified third-party target. These controls are currently skill-level and operator-enforced; deterministic Python and MCP scope enforcement is planned but not currently implemented. The skills explicitly exclude active exploitation, post-exploitation, malware development, persistence, evasion, and other activities beyond OSINT-driven reconnaissance. See [`SECURITY.md`](SECURITY.md) for the full posture.

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

> *Raw recon tells you what exists. Outrider helps decide what matters first.*
