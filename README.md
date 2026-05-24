![claude-osint banner](assets/banner.png)

# claude-osint

> Modular Claude skills · **90+ recon modules** · 48 secret-regex patterns · 80+ dorks · 9 read-only credential validators · 27 attack-path templates. Drop-in `SKILL.md` files that turn Claude into a focused external recon operator for authorized red-team and bug-bounty engagements.

Built by **[ElementalSoul](https://github.com/elementalsouls)** — GenAI Security Research.

---

## What is this?

`claude-osint` is a modular set of skills for the [Claude skills system](https://docs.claude.com/en/docs/claude-code/skills). Each skill is a structured `SKILL.md` file that primes Claude with expert-level methodology for a specific slice of the offensive recon problem:

- **`osint-methodology`** — *how to think.* Strategic + procedural. Asset-graph discipline, severity rubric, time budgeting, identity-fabric mapping, deliverable templates.
- **`offensive-osint`** — *router.* Dispatches to the right sub-skill based on task type. Load this first; it tells Claude which focused sub-skill to reach for.
- **`identity-fabric`** — *IdP + SSO surface.* Concrete endpoints for Entra, Okta, ADFS, SAML, M365 deep enum, GraphQL field-suggestion, LinkedIn employee enum.
- *(additional sub-skills being added — see [Skill Index](#skill-index) for the full capability map)*

Drop the skills into your Claude environment and it behaves like a senior recon analyst: it knows the techniques, the tooling, the edge cases, and the escalation paths — and it stays in scope.

96.9% PASS on a 32-prompt self-evaluation · ~85–90% practitioner coverage for the recon phase of authorized engagements.

---

## Structure

```
claude-osint/
├── skills/
│   ├── osint-methodology/SKILL.md     # how to think
│   ├── offensive-osint/SKILL.md       # router — dispatches to sub-skills below
│   ├── identity-fabric/SKILL.md       # Entra · Okta · ADFS · SAML · M365 · LinkedIn
│   └── report-template/SKILL.md      # bug-bounty report scaffold
├── skills/offensive-osint/scripts/
│   ├── h1_reference.py               # HackerOne disclosed-reports reference agent (no API key)
│   └── secret_scan.py                # stdlib-only secret scanner (JSONL output)
├── scripts/
│   └── sync-skill-content.sh         # restore full skill content from docs/full-skills/
├── docs/                              # architecture · coverage · install · usage
├── examples/                          # 4 end-to-end engagement walk-throughs
├── tests/smoke-test-prompts.md        # 32-prompt self-evaluation
├── CLAUDE.md.example                  # copy to CLAUDE.md and customise for your engagement
└── assets/banner.png
```

Each skill directory is self-contained. Drop into `~/.claude/skills/` and Claude auto-triggers on relevant phrases.

---

## Skill Index

90+ capabilities across 12 domains. Categorized like Claude-Red — pick a domain to drill in.

### Reconnaissance & Asset Discovery

| Capability | Skill |
|---|---|
| 5-stage external recon pipeline + time-budget profiles (1h / 4h / 1d / 1w) | methodology |
| Subdomain-source stack (crt.sh + 7-source fallback chain when crt.sh 502s) | arsenal |
| Common-prefix subdomain sweep (100+ ordered prefixes, PowerShell + bash) | arsenal |
| Wayback CDX deep mining + legacy-app pivot (.asp/.php/.jsp/.cfm) | arsenal |
| WHOIS / RDAP / historical-WHOIS + reverse-WHOIS pivots | arsenal |
| Public records (OpenCorporates · SEC EDGAR · GSXT · Rusprofile · Companies House) | arsenal |
| Bulk IP → ASN (Cymru / RIPEstat / bgp.tools) | arsenal |

### Identity & SSO Mapping

| Capability | Skill |
|---|---|
| Microsoft Entra (Azure AD) tenant fingerprint + GUID extraction | arsenal |
| M365 deep enum (Teams federation · SharePoint · OneDrive · OAuth · device-code phishing) | arsenal |
| Autodiscover IP correlation (passive M365 confirm even when MX wrapped by Mimecast/Proofpoint) | arsenal |
| Okta tenant slug + `/api/v1/authn` user-enum | arsenal |
| ADFS fingerprint + mex endpoint | arsenal |
| Google Workspace OIDC discovery | arsenal |
| Generic OIDC (Auth0 · Keycloak · Ping · OneLogin · Duo) | arsenal |
| SAML metadata (5 paths) | arsenal |
| AWS account-ID extraction from headers + ARN regex | arsenal |

### Web Application Attack Surface

| Capability | Skill |
|---|---|
| Swagger / OpenAPI discovery (28 paths) | arsenal |
| GraphQL discovery + introspection POST body (13 paths) | arsenal |
| GraphQL field-suggestion enum (when introspection disabled) + alias batching + depth bypass | arsenal |
| Always-on HTTP checks (15 paths: .git/.env/actuator/heapdump/etc.) | arsenal |
| Missing security header audit (HSTS/CSP/XFO/etc.) | arsenal |
| Endpoint extraction regex tiers (3 tiers) | arsenal |
| Endpoint interest score (0–100 rubric) | arsenal |
| JS deep analysis · sourcemap leakage · internal-host regex | arsenal |
| Subdomain takeover fingerprints (27 providers) | arsenal |

### Cloud & Container

| Capability | Skill |
|---|---|
| Cloud bucket arsenal (S3 / GCS / Azure · 6 prefixes × 15 suffixes × 47 stems) | arsenal |
| Cloud-native fingerprints (Lambda URLs · Cloud Run · Azure Functions · Vercel · Netlify · Workers) | arsenal |
| Kubernetes / etcd / kubelet exposure (12 ports + probes) | arsenal |
| Container registry leak hunting (Docker Hub · Quay · GHCR · ECR · GCR · ACR) | arsenal |
| CI/CD platform exposure (Jenkins · GitLab · TeamCity-KEV · Argo CD · Spinnaker · CircleCI) | arsenal |

### Secret & Credential Hunting

| Capability | Skill |
|---|---|
| 48-pattern secret-regex catalog (29 base + 19 modern) | arsenal |
| Modern AI API keys (Anthropic / OpenAI / HuggingFace / Cloudflare) | arsenal (rows 30-36) |
| Package-registry tokens (npm / PyPI / Docker Hub) | arsenal (rows 38-40) |
| GitHub code-search dorks (13 templates) | arsenal |
| 9 read-only credential validators (Postman / AWS / GitHub / Slack / Anthropic / OpenAI / npm / Atlassian / DataDog) | arsenal |
| Post-discovery enumeration workflows (IAM enum · repo enum · workspace enum · JWT triage) | arsenal |
| `secret_scan.py` — stdlib-only secret scanner (JSONL output) | scripts |
| `h1_reference.py` — HackerOne disclosed-reports reference (top-voted / keyword / program filter) | scripts |
| 80+ dork corpus across 9 categories | arsenal |

### Breach Intelligence

| Capability | Skill |
|---|---|
| HudsonRock Cavalier direct API (free; FYI: web-UI wraps a public JSON endpoint) | arsenal |
| Domain-level breach severity mapping | arsenal |
| `SSO_EXPOSURE` finding + legacy-mail-decommissioned escalation pattern | arsenal |
| Breach × identity correlation (HudsonRock + HIBP + DeHashed + IntelX) | methodology |

### Vendor & Edge-Appliance Fingerprinting

| Capability | Skill |
|---|---|
| Citrix Netscaler · F5 BIG-IP · Pulse Secure / Ivanti · FortiGate | arsenal |
| PaloAlto GlobalProtect · Cisco AnyConnect · VMware vCenter / ESXi / Horizon | arsenal |
| Microsoft Exchange OWA (ProxyShell / ProxyLogon / ProxyNotShell) | arsenal |
| KEV CVE enrichment + EPSS scoring + Metasploit availability | arsenal |
| WAF / CDN bypass + origin discovery (8 techniques) | methodology, arsenal |

### Email Security

| Capability | Skill |
|---|---|
| SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT / DNSSEC audit (bash + PowerShell) | arsenal |
| DMARC reporting-vendor inference (Kratikal / dmarcian / Valimail / Agari / EasyDMARC) | arsenal |
| TXT verification token catalog (35+ SaaS tenants) | arsenal |
| MX → IdP / mail-host inference | arsenal |

### Human Intelligence

| Capability | Skill |
|---|---|
| LinkedIn employee enumeration (P0–P5 role tiers · sock-puppet hygiene) | arsenal |
| Job posting tech-stack analysis (Lever · Greenhouse · AshbyHQ · Workable) | arsenal |
| Slack / Discord / Telegram / Mattermost workspace discovery | arsenal |
| Sat imagery for physical recon (Google Earth · NearMap · Sentinel Hub) | arsenal |
| Email-pattern inference (8 templates) | arsenal |

### Supply Chain

| Capability | Skill |
|---|---|
| Package-registry leak hunting (npm · PyPI · RubyGems · Cargo · Packagist · NuGet · Maven) | arsenal |
| Typosquat surveillance | arsenal |
| Postman public-workspace search (verified endpoint) | arsenal |
| Stack Exchange OSINT sweep (8 sites) | arsenal |

### Reporting & Deliverables

| Capability | Skill |
|---|---|
| Findings rubric (CRITICAL/HIGH/MED/LOW/INFO + escalation) | methodology |
| Severity decision matrix (88 worked examples) | arsenal |
| Attack-path hint patterns (27 templates) | arsenal |
| Bug-bounty submission templates (HackerOne / Bugcrowd / Intigriti) | methodology |
| Client deliverable templates (exec summary · risk-translation matrix · cadence) | methodology |
| Reproduction package | methodology |

### Sector-Specific

| Capability | Skill |
|---|---|
| Healthcare (DICOM · HL7 v2 · FHIR · Epic / Cerner / Allscripts) | arsenal |
| Finance (SWIFT · FIX · Bloomberg · Temenos / Finacle / FIS / Fiserv) | arsenal |
| ICS / SCADA (Modbus · BACnet · Siemens S7 · DNP3 · EtherNet/IP) | arsenal |
| IoT (MQTT · CoAP · UPnP · Hikvision / Dahua DVRs) | arsenal |
| Government (`.gov` / `.mil` · FedRAMP · FISMA · CUI · SAM.gov) | arsenal |

---

## Capability Map

Two skills, twelve capability domains. Drill into the [Skill Index](#skill-index) above for concrete sub-capabilities.

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#1e293b','primaryTextColor':'#f1f5f9','primaryBorderColor':'#475569','lineColor':'#94a3b8'}}}%%
flowchart LR
    Root(["🦅 claude-osint"])

    Root --> M["📘 osint-methodology<br/><i>how to think</i>"]
    Root --> R["🗺️ offensive-osint<br/><i>router</i>"]

    M --> M1[Recon Pipeline]
    M --> M2[Asset Graph]
    M --> M3[Findings Rubric]
    M --> M4[Reporting Templates]
    M --> M5[OpSec & Detectability]

    R --> S1["🔍 recon-asset-discovery<br/><i>subdomains · DNS · ASN · CT</i>"]
    R --> S2["🌐 web-surface<br/><i>probes · Swagger · GraphQL · Wayback</i>"]
    R --> S3["🪪 identity-fabric<br/><i>Entra · Okta · ADFS · M365 · LinkedIn</i>"]
    R --> S4["🔑 secrets-and-dorks<br/><i>48 regexes · 80+ dorks · validators</i>"]
    R --> S5["⚡ post-discovery<br/><i>JWT · AWS IAM · GitHub · Slack enum</i>"]
    R --> S6["☁️ cloud-and-infra<br/><i>cloud-native · K8s · CI-CD</i>"]
    R --> S7["👥 people-breach-intel<br/><i>breach · HudsonRock · crypto · media</i>"]
    R --> S8["📊 analysis-and-reporting<br/><i>scoring · severity matrix · archiving</i>"]

    style Root fill:#dc2626,stroke:#7f1d1d,color:#fff
    style M fill:#1e293b,stroke:#475569,color:#f1f5f9
    style R fill:#7c2d12,stroke:#9a3412,color:#fef3c7
    style M1 fill:#0f172a,stroke:#334155,color:#cbd5e1
    style M2 fill:#0f172a,stroke:#334155,color:#cbd5e1
    style M3 fill:#0f172a,stroke:#334155,color:#cbd5e1
    style M4 fill:#0f172a,stroke:#334155,color:#cbd5e1
    style M5 fill:#0f172a,stroke:#334155,color:#cbd5e1
    style S1 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S2 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S3 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S4 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S5 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S6 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S7 fill:#1c1917,stroke:#44403c,color:#fed7aa
    style S8 fill:#1c1917,stroke:#44403c,color:#fed7aa
```

---

## Engagement Flow

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#1e293b','primaryTextColor':'#f1f5f9','primaryBorderColor':'#475569','lineColor':'#94a3b8'}}}%%
flowchart TD
    A["🎯 Target authorized<br/><i>RoE / BB scope / ASM contract</i>"] --> B[methodology<br/>scope check]
    B --> C[methodology<br/>5-stage pipeline]

    C --> D1["🔍 Stage 1<br/>Seed Discovery"]
    C --> D2["🌐 Stage 2<br/>Asset Expansion"]
    C --> D3["📊 Stage 3<br/>Enrichment"]
    C --> D4["⚠️ Stage 4<br/>Exposure Analysis"]
    C --> D5["📋 Stage 5<br/>Reporting"]

    D1 --> E1[DNS catalog<br/>WHOIS / RDAP<br/>public records]
    D2 --> E2[subdomain stack<br/>prefix sweep<br/>Wayback CDX]
    D3 --> E3[vendor fingerprint<br/>identity fabric<br/>infrastructure OSINT]
    D4 --> E4[secret catalog<br/>always-on HTTP checks<br/>K8s exposure<br/>read-only validators<br/>breach × identity]
    D5 --> E5[severity rubric<br/>BB submission<br/>client deliverable]

    E1 --> F[methodology<br/>asset graph]
    E2 --> F
    E3 --> F
    E4 --> G["📋 Findings<br/>severity + confidence + evidence"]
    E5 --> H["📦 Deliverable<br/>exec summary + repro package"]

    F --> G

    style A fill:#3b82f6,color:#fff
    style B fill:#7c2d12,color:#fef3c7
    style C fill:#1e293b,color:#f1f5f9
    style F fill:#7c3aed,color:#fff
    style G fill:#dc2626,color:#fff
    style H fill:#14532d,color:#dcfce7
```

---

## Usage

### With Claude Code

```bash
# 1. Clone and install skills
git clone https://github.com/elementalsouls/Claude-OSINT.git
mkdir -p ~/.claude/skills
cp -r Claude-OSINT/skills/* ~/.claude/skills/

# 2. Set up your local Claude config
cp Claude-OSINT/CLAUDE.md.example Claude-OSINT/CLAUDE.md
# Edit CLAUDE.md — fill in your platform and handle for traffic tagging
```

Then in any Claude Code session, ask an OSINT question — skills auto-load and trigger on relevant phrases.

### With the Claude Skills System

```bash
# Point Claude at a single skill before starting your session
cat skills/offensive-osint/SKILL.md | claude --system-file -
```

### Manual (Claude.ai / Claude API)

Paste the contents of any `SKILL.md` into a Project's system prompt or prepend it to your conversation. Both files are plain Markdown — also usable as a personal cheat-sheet without Claude.

---

## Authorization

These skills are intended for assets you **own** or have **written authorization to assess** (red-team rules of engagement, bug-bounty in-scope assets, ASM contracts).

Both skills include a soft scope-check when you ask Claude to act against an unverified third-party target. They explicitly **exclude** active exploitation, post-exploitation, malware development, and other activities beyond OSINT-driven reconnaissance. See [`SECURITY.md`](SECURITY.md) for the full posture.

---

## Documentation

| Doc | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Design philosophy · asset-graph model · confidence/severity/detectability models · sidecar coordination · diagrams |
| [`docs/coverage.md`](docs/coverage.md) | Honest practitioner-coverage breakdown by archetype + engagement phase |
| [`docs/installation.md`](docs/installation.md) | Symlink installs and multi-environment install patterns |
| [`docs/usage.md`](docs/usage.md) | Trigger-phrase reference and prompt templates |
| [`examples/`](examples/) | 4 end-to-end engagement walk-throughs (quick recon · bug-bounty · M365 deep · secret hunting) |
| [`tests/smoke-test-prompts.md`](tests/smoke-test-prompts.md) | 32-prompt self-evaluation suite (current grade: 31/32 PASS) |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Pull-request guidelines |

---

## About

Operational tradecraft accumulated across external attack-surface engagements, codified into Claude skills. Engagement-platform agnostic - slot into any ASM / ticketing / asset-graph platform you already use, or none.

**Author:** [ElementalSoul](https://github.com/elementalsouls)

**Original framework:** [SnailSploit/offensive-checklist](https://github.com/SnailSploit/offensive-checklist) (v1.x)

**Inspired by:** [Bellingcat's Online Investigations Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) 
· [IntelTechniques](https://inteltechniques.com/tools/) 
· [OSINT Framework](https://osintframework.com/)

**Tool inventory:** 
. [ProjectDiscovery](https://github.com/projectdiscovery) 
· [Six2dez reconftw](https://github.com/six2dez/reconftw) 
· [SecLists](https://github.com/danielmiessler/SecLists) 
· [Assetnote Wordlists](https://wordlists.assetnote.io/)

**License:** [MIT](LICENSE) — use freely, attribution appreciated.

---

> *"Give Claude the right skill and it stops being a chatbot. It becomes an operator."*
