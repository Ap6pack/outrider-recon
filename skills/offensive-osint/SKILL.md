---
name: offensive-osint
description: "Router for the Offensive OSINT arsenal. Dispatches to focused sub-skills by task type. Covers the full external red-team surface: asset discovery, web enumeration, identity/SSO, secrets/dorks, post-credential workflows, cloud/infra, people/breach intel, and analysis/reporting. Companion to osint-methodology. Use for any authorized external recon, bug bounty, or ASM engagement."
version: 2.1.1
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - ASM
  - bug bounty recon
  - bug bounty
  - reconnaissance
  - footprinting
  - asset discovery
  - start recon
  - new target
  - pick up recon
  - continue recon
  - assess target
---

# Offensive OSINT — Arsenal Router

> Companion: `osint-methodology` — pipeline stages, triage rules, severity rubric. Load it alongside this router at the start of every session.

**Scope gate:** Authorized targets only. When scope is unclear, ask once before proceeding.

---

## BEHAVIORAL CONTRACT

**When triggered:** Any external recon, bug bounty, ASM engagement, or general "where do I start" offensive OSINT request.

**Execute:**
1. Load `osint-methodology` — identify the pipeline stage and scope.
2. Match the current task to a sub-skill using the sub-skill map below.
3. Load that sub-skill and begin execution immediately.
4. Propose the next concrete action without waiting to be asked.
5. When one sub-skill's work completes, chain to the next relevant sub-skill autonomously — follow the pipeline priority order from `osint-methodology` §7.1.

**Output:** Delegation to the appropriate sub-skill(s). This router produces no findings itself.

**Gating rules:** Authorized targets only. When scope is unclear, ask once before proceeding. Hard rules (below) are always-on across all sub-skills.

**Chain to:** Autonomously chain through sub-skills following `osint-methodology` §7.1 priority order: breaches → GitHub recon → misconfig sweep → cloud buckets → ports → email OSINT → web tech → Wayback → DNS/email security → certs/TLS → ASN/reverse DNS → typosquats.

---

## Sub-skill map

Load the sub-skill that matches the current task. Each is self-contained and under 500 lines.

| Task | Sub-skill to load |
|---|---|
| Subdomains, ASN/BGP, DNS, CT, WHOIS/RDAP, wordlists | `recon-asset-discovery` |
| Web surface: Swagger/GraphQL paths, curl probes, Wayback, Postman, endpoint scoring | `web-surface` |
| IdP fingerprinting, Entra/Okta/ADFS/SAML, M365 deep enum, LinkedIn employee enum | `identity-fabric` |
| Secret regexes, dork corpus, GitHub code-search dorks, read-only validators | `secrets-and-dorks` |
| Post-credential: JWT triage, AWS IAM enum, GitHub scope enum, Slack workspace enum | `post-discovery` |
| Cloud-native fingerprints, K8s/container, CI/CD exposure, infra OSINT | `cloud-and-infra` |
| Username/email/phone, breach data, HudsonRock, Slack/Discord/Telegram, package registries | `people-breach-intel` |
| Scoring rubrics, attack-path hints, severity matrix, AI-assisted OSINT, archiving | `analysis-and-reporting` |
| Report generation: bug-bounty submission, client deliverable, vulnerability report | `report-template` |

---

## Session start checklist

1. Load `osint-methodology` — identify the pipeline stage and scope.
2. Load the sub-skill matching the current task from the map above.
3. Propose the next concrete action without waiting to be asked.

---

## Hard rules (always-on, all sub-skills)

- Never report a bypass without demonstrated impact.
- Run read-only validators (`secrets-and-dorks`) before escalating any credential finding.
- `post-discovery` is gated — confirm read-only validation passes first.
- No destructive probes. No active scanning outside explicit written scope.
