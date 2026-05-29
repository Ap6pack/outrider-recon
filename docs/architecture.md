# Architecture & Design Philosophy

## The router + sub-skill split

The skills are split into **methodology** ("how to think"), a **router** ("which sub-skill handles this"), and **9 focused sub-skills** ("what to reach for"). This reflects how practitioners actually work:

- **Methodology mode** — "I have a target. How do I approach this?" → strategic + procedural.
- **Arsenal mode** — "I need a Swagger probe path / secret regex / curl one-liner." → tactical + reference.

A single mega-skill of ~4,200 lines would have noisier triggering and worse retrieval. The split lets each skill have a tight, distinct trigger vocabulary and a behavioral contract that drives autonomous execution.

```mermaid
flowchart TD
    U["USER ASKS:<br/><i>'How do I find an origin behind Cloudflare?'</i>"]
    M["📘 osint-methodology §6.4 + docs/methods/cdn-bypass-techniques.md<br/>technique catalog + confidence rules"]
    A["🛠️ cloud-and-infra §5 + docs/methods/cdn-bypass-techniques.md<br/>actual curl commands"]
    O["✅ Composed answer"]
    U --> M
    U --> A
    M --> O
    A --> O
    style U fill:#3b82f6,color:#fff
    style M fill:#1e293b,color:#f1f5f9
    style A fill:#7c2d12,color:#fef3c7
    style O fill:#14532d,color:#dcfce7
```

> Most prompts pull both. They're complementary, not overlapping.

## Confidence model

Every assertion carries a graded confidence level:

```mermaid
flowchart LR
    T["🟡 TENTATIVE<br/>1 source · inferred pattern"]
    F["🟠 FIRM<br/>2+ sources OR direct observation"]
    C["🟢 CONFIRMED<br/>verified + multiple independent corroborations"]
    T -->|+ corroborating evidence| F
    F -->|+ verification| C
    style T fill:#ca8a04,color:#fff
    style F fill:#ea580c,color:#fff
    style C fill:#16a34a,color:#fff
```

Per-asset-type upgrade workflows in `osint-methodology` §2.1 specify exactly what evidence moves an asset between levels.

## Severity model

Severity is **operational**, anchored on examples. The methodology rubric (§9) defines tiers:

```mermaid
flowchart TD
    CRIT["🔴 CRITICAL<br/>Pre-auth RCE · valid creds · listable prod data · trust violations"]
    HIGH["🟠 HIGH<br/>Sourcemap · open GraphQL introspection · takeover · reflected CORS+creds · exposed admin UI"]
    MED["🟡 MEDIUM<br/>Missing headers · info disclosure · hardening gaps · brute-force exposure"]
    LOW["🟢 LOW<br/>Cosmetic · marginal hardening"]
    INFO["⚪ INFO<br/>Recordable · no immediate action"]
    CRIT --> HIGH --> MED --> LOW --> INFO
    style CRIT fill:#7f1d1d,color:#fff
    style HIGH fill:#9a3412,color:#fff
    style MED fill:#a16207,color:#fff
    style LOW fill:#15803d,color:#fff
    style INFO fill:#475569,color:#fff
```

The severity matrix in `analysis-and-reporting` provides 92 worked examples for triage. Escalation rules cover special cases (HSTS missing on `/login` → MED→HIGH, etc.).

## Detectability model

Every probe carries a detectability tag:

```mermaid
flowchart LR
    L["🟢 LOW<br/>Passive sources<br/>CT logs · Wayback · Shodan InternetDB · Hunter.io"]
    M["🟡 MEDIUM<br/>Targeted probes<br/>user-enum · validator queries · GraphQL probes · screenshots"]
    H["🔴 HIGH<br/>Active scans<br/>port scans · Nuclei full templates · web fuzzing · brute-force"]
    L --> M --> H
    style L fill:#15803d,color:#fff
    style M fill:#a16207,color:#fff
    style H fill:#7f1d1d,color:#fff
```

The detection-aware probing section (`osint-methodology` §6.4) provides the back-off ladder for when you start hitting active defenses.

## Asset graph model

```mermaid
flowchart TD
    Domain["🌐 Domain"]
    Subdomain["🔗 Subdomain"]
    IP["📡 IP"]
    ASN["🏢 ASN"]
    WebApp["💻 WebApp"]
    ApiSpec["📜 ApiSpec"]
    Secret["🔑 Secret"]
    Email["📧 Email"]
    Person["👤 Person"]
    Breach["💥 Breach"]
    Domain -->|ALIAS_OF / RESOLVES_TO| Subdomain
    Subdomain -->|RESOLVES_TO| IP
    IP -->|IN_NETBLOCK| ASN
    Subdomain -->|HOSTED_ON| ASN
    Subdomain -->|EXPOSES| WebApp
    WebApp -->|DOCUMENTED_BY| ApiSpec
    WebApp -->|CONTAINS_SECRET| Secret
    Secret -->|BREACHED_FROM| Breach
    Breach -->|CONTAINS| Email
    Email -->|EMPLOYED_BY| Person
    style Domain fill:#1e40af,color:#fff
    style Subdomain fill:#1e40af,color:#fff
    style IP fill:#0891b2,color:#fff
    style ASN fill:#0891b2,color:#fff
    style WebApp fill:#7c3aed,color:#fff
    style ApiSpec fill:#7c3aed,color:#fff
    style Secret fill:#dc2626,color:#fff
    style Breach fill:#dc2626,color:#fff
    style Email fill:#ea580c,color:#fff
    style Person fill:#ea580c,color:#fff
```

29 asset types organized in 9 categories. 23 typed edges. Discipline: every discovery is a typed asset (never a free-floating string), with provenance tracked.

## Output schema

Findings are structured for ingestion by asset-management tools:

```yaml
Finding:
  id:           <stable hash or UUID>
  module:       <which technique discovered it>
  asset_key:    <typed asset key, e.g., sub:api.example.com>
  category:     <e.g., SECRET_LEAK, OPEN_GRAPHQL_API, SSO_EXPOSURE>
  severity:     critical | high | medium | low | info
  confidence:   confirmed | firm | tentative
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:
    url:        <where it was found>
    timestamp:  <UTC ISO8601>
    sha256:     <hash of any artifact>
    raw:        <truncated to 2 KiB>
  references:
    - <CVE-ID, advisory URL, vendor doc>
  remediation:  <action the asset owner can take>
```

This shape is portable to any asset / findings store (ASM platforms, ticketing systems, custom DBs).

## Cross-module sidecar coordination

When techniques produce outputs that feed other techniques, sidecar JSON files enable late binding:

```mermaid
flowchart LR
    M["📱 mobile_attack_surface"] -->|writes| J["📄 mobile_endpoints.json"]
    J -->|reads| A["🔌 api_discovery"]
    style M fill:#7c3aed,color:#fff
    style J fill:#475569,color:#f1f5f9
    style A fill:#7c3aed,color:#fff
```

Patterns documented in `analysis-and-reporting` §6.

## Validator discipline

Credential validators are **read-only by design**. Never destructive.

```mermaid
flowchart LR
    D["🔍 Discovery<br/><i>catalog regex</i>"]
    V["✅ Validation<br/><i>read-only<br/>/me · /user · auth.test</i>"]
    S["🗺️ Scope-enum<br/><i>read-only<br/>IAM · repo · workspace</i>"]
    A["🎯 Attack-path-hint<br/><i>operator pivots from here</i>"]
    D --> V --> S --> A
    style D fill:#1e40af,color:#fff
    style V fill:#15803d,color:#fff
    style S fill:#7c3aed,color:#fff
    style A fill:#9a3412,color:#fff
```

9 providers covered (Postman, AWS, GitHub, Slack, Anthropic, OpenAI, npm, Atlassian, DataDog). Hard rule: never create / delete / send. Tag every validation with detectability + `checked_at`.

## Trigger frontmatter discipline

Each skill declares ~50–110 trigger phrases in YAML frontmatter. Triggers are:

- The exact wording a user would type (`kubelet exposed`, not `Kubernetes Kubelet API exposure on port 10250`).
- Inclusive of common synonyms (`SSO discovery`, `IdP fingerprinting`, `tenant fingerprinting` all map to identity-fabric work).
- Domain-specific jargon (`JARM`, `mmh3`, `BGP`, `KEV`).
- Operator slang (`grease the rails`, `pop the recon`).

## Versioning

Semantic versioning. The `version:` field in YAML frontmatter is authoritative.

- **MAJOR** — section renumbering, breaking trigger changes, schema changes to Finding output.
- **MINOR** — new sections, new techniques, expanded catalogs.
- **PATCH** — typo fixes, link updates, severity-tier corrections.

Current project release: v3.0. Individual skill versions in YAML frontmatter.

## Renumbering policy

When new top-level sections are added in a minor release, existing sections may renumber. The CHANGELOG records mappings.

Subsection numbering is generally additive (§7.6 added without renumbering §7.5).

## What's deliberately excluded

By design, the skills do NOT cover:

- **Active exploitation** (PoC code, exploit chains)
- **Post-exploitation** (lateral movement, privesc, persistence)
- **Active Directory** (BloodHound, Kerberoasting, SMB relay)
- **Malware development** (payload crafting, AV/EDR evasion)
- **C2 frameworks** (Cobalt Strike, Sliver, Mythic, Havoc)
- **Real PII / credentials / breach corpus content** in examples
- **Defensive / blue-team detection** content (different domain)
- **Pricing / NDA / SOW templates** (business operations, not technical)

These exclusions are intentional. A "comprehensive offensive security" skill would be a textbook, not a focused tool. We'd rather do one thing well than many things adequately.

## Capability Map

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#1e293b','primaryTextColor':'#f1f5f9','primaryBorderColor':'#475569','lineColor':'#94a3b8'}}}%%
flowchart LR
    Root(["🦅 outrider-recon"])

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
    R --> S4["🔑 secrets-and-dorks<br/><i>48 regexes · 70 dorks · validators</i>"]
    R --> S5["⚡ post-discovery<br/><i>JWT · AWS IAM · GitHub · Slack enum</i>"]
    R --> S6["☁️ cloud-and-infra<br/><i>cloud-native · K8s · CI-CD</i>"]
    R --> S7["👥 people-breach-intel<br/><i>breach · HudsonRock · Slack/Discord/Telegram</i>"]
    R --> S8["📊 analysis-and-reporting<br/><i>scoring · severity matrix · archiving</i>"]
    R --> S9["📝 report-template<br/><i>BB submission · client deliverable</i>"]

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
    style S9 fill:#1c1917,stroke:#44403c,color:#fed7aa
```

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

## Engagement-platform agnostic

These skills are extracted from operational tradecraft accumulated across external attack-surface engagements. The 81 capabilities generalize to any OSINT engagement and slot into any ASM / ticketing / asset-graph platform you already use -- or none.

Use the skills standalone (paste a SKILL.md into a Claude Project) or wired into your own pipeline.
