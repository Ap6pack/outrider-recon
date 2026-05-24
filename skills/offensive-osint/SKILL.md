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

## Sub-skill map

Load the sub-skill that matches the current task. Each is self-contained and under 500 lines.

| Task | Sub-skill to load |
|---|---|
| Subdomains, ASN/BGP, DNS, CT, WHOIS/RDAP, geospatial, regional engines | `recon-asset-discovery` |
| Web surface: Swagger/GraphQL paths, curl probes, Wayback, Postman, endpoint scoring | `web-surface` |
| IdP fingerprinting, Entra/Okta/ADFS/SAML, M365 deep enum, LinkedIn employee enum | `identity-fabric` |
| Secret regexes, dork corpus, GitHub code-search dorks, read-only validators | `secrets-and-dorks` |
| Post-credential: JWT triage, AWS IAM enum, GitHub scope enum, Slack workspace enum | `post-discovery` |
| Cloud-native fingerprints, K8s/container, CI/CD exposure, infra OSINT | `cloud-and-infra` |
| Username/email/phone, people search, breach data, HudsonRock, crypto, media, Telegram | `people-breach-intel` |
| Scoring rubrics, attack-path hints, severity matrix, AI-assisted OSINT, archiving | `analysis-and-reporting` |

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
