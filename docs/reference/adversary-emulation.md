# Adversary-Emulation Playbooks — External Recon Phase

> Reference for simulating specific threat actors' external reconnaissance
> techniques. OSINT-phase only — no exploitation, C2, or post-exploit.

---

## Methodology

Map each emulation to [MITRE ATT&CK Reconnaissance (TA0043)](https://attack.mitre.org/tactics/TA0043/) techniques, then execute the corresponding outrider-recon skill. Every finding should carry an ATT&CK technique ID so purple-team handoffs are immediate.

### ATT&CK Reconnaissance Technique Mapping

| ATT&CK ID | Technique Name | outrider-recon Skill / Section |
|------------|---------------|-------------------------------|
| T1595.001 | Active Scanning: IP Blocks | `recon-asset-discovery` (port/service enumeration) |
| T1595.002 | Active Scanning: Vulnerability Scanning | `web-surface` (service fingerprinting) |
| T1595.003 | Active Scanning: Wordlist Scanning | `web-surface` (content discovery, directory brute-force) |
| T1592.001 | Gather Victim Host Info: Hardware | `web-surface` (banner grabbing, device fingerprints) |
| T1592.002 | Gather Victim Host Info: Software | `web-surface` (technology profiling via Wappalyzer, BuiltWith) |
| T1592.004 | Gather Victim Host Info: Client Configs | `identity-fabric` (Entra/M365 tenant discovery) |
| T1589.001 | Gather Victim Identity Info: Credentials | `people-breach-intel` (breach database lookups) |
| T1589.002 | Gather Victim Identity Info: Email Addresses | `people-breach-intel` (email harvesting) |
| T1589.003 | Gather Victim Identity Info: Employee Names | `people-breach-intel` (LinkedIn enumeration) |
| T1590.001 | Gather Victim Network Info: Domain Properties | `recon-asset-discovery` (DNS, WHOIS, CT logs) |
| T1590.002 | Gather Victim Network Info: DNS | `recon-asset-discovery` (subdomain enumeration) |
| T1590.004 | Gather Victim Network Info: Network Topology | `cloud-and-infra` (ASN mapping, BGP analysis) |
| T1591.001 | Gather Victim Org Info: Physical Locations | `osint-methodology` (geospatial OSINT) |
| T1591.002 | Gather Victim Org Info: Business Relationships | `people-breach-intel` (supply chain, vendor mapping) |
| T1591.004 | Gather Victim Org Info: Roles | `identity-fabric` (org chart reconstruction) |
| T1593.001 | Search Open Websites/Domains: Social Media | `people-breach-intel` (social media profiling) |
| T1593.002 | Search Open Websites/Domains: Search Engines | `secrets-and-dorks` (Google dorking, GitHub code search) |
| T1593.003 | Search Open Websites/Domains: Code Repos | `secrets-and-dorks` (secret scanning, repo analysis) |
| T1594 | Search Victim-Owned Websites | `web-surface` (crawling, JS analysis, endpoint extraction) |
| T1596.001 | Search Open Tech Databases: DNS/Passive DNS | `recon-asset-discovery` (passive DNS pivots) |
| T1596.002 | Search Open Tech Databases: WHOIS | `recon-asset-discovery` (historical WHOIS, reverse WHOIS) |
| T1596.003 | Search Open Tech Databases: Digital Certs | `recon-asset-discovery` (CT log enumeration, cert pivots) |
| T1596.005 | Search Open Tech Databases: Scan Databases | `recon-asset-discovery` (Shodan, Censys, BinaryEdge) |
| T1597.001 | Search Closed Sources: Threat Intel Vendors | `analysis-and-reporting` (threat-intel correlation) |
| T1598 | Phishing for Information | `osint-methodology` (phishing infrastructure assessment) |

---

## APT29 (Cozy Bear / The Dukes)

**Profile.** State-sponsored (Russia/SVR). Known for patient, low-and-slow campaigns targeting government, diplomatic, and cloud-heavy enterprises. Heavy use of cloud-native living-off-the-land techniques post-compromise, which shapes their recon focus toward cloud identity surfaces.

### Known Recon Patterns

- Cloud/SaaS focus: M365 tenant enumeration, Azure AD (Entra ID) configuration discovery, OAuth application grants.
- Federation endpoint probing: ADFS, PingFederate, Okta — seeking SSO misconfigurations.
- Service principal and application registration reconnaissance in public Entra ID endpoints.
- Supply chain interest: SolarWinds-style vendor trust mapping.

### Emulation with outrider-recon

| Phase | Skill | Specific Actions |
|-------|-------|-----------------|
| Identity surface | `identity-fabric` | Entra ID tenant discovery, federation endpoint enumeration, OAuth app registration analysis, MFA policy inference |
| Web surface | `web-surface` | OAuth/OIDC endpoint discovery (`.well-known/openid-configuration`), ADFS metadata enumeration, service principal login pages |
| Secret hunting | `secrets-and-dorks` | GitHub code search for Azure client secrets, tenant IDs in public repos, cloud credential patterns (`AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`) |
| Vendor mapping | `people-breach-intel` | LinkedIn employee enumeration for cloud-admin roles, vendor relationship mapping |

### Priority Targets

- Cloud admin portals (`portal.azure.com`, `admin.microsoft.com` login surfaces)
- Federation/SSO endpoints (ADFS, Okta, PingFederate metadata URLs)
- Service principal configurations exposed via Entra ID open endpoints
- OAuth consent grant surfaces and application registration pages

---

## APT28 (Fancy Bear / Sofacy)

**Profile.** State-sponsored (Russia/GRU Unit 26165). Aggressive campaigns against government, military, media, and political organizations. Favors credential harvesting and spear-phishing. Targets edge infrastructure (VPNs, email gateways) for initial access.

### Known Recon Patterns

- Email harvesting at scale: building per-org email address lists for credential-phishing campaigns.
- Credential breach correlation: matching harvested emails against known breach datasets.
- VPN concentrator and edge-device fingerprinting: identifying make/model/version for exploit targeting.
- Webmail and OWA portal discovery for credential-spraying preparation.

### Emulation with outrider-recon

| Phase | Skill | Specific Actions |
|-------|-------|-----------------|
| Email harvest | `people-breach-intel` | Hunter.io domain search, LinkedIn employee enumeration via CrossLinked, email-pattern generation, Holehe registration checks |
| Breach correlation | `people-breach-intel` | Breach database lookups for harvested emails, credential-exposure timeline analysis |
| Edge infrastructure | `web-surface` | Vendor fingerprinting for VPN concentrators (Cisco AnyConnect, Fortinet, Pulse Secure), webmail portal discovery (OWA, Zimbra, Roundcube) |
| Phishing infra recon | `osint-methodology` | Look-alike domain enumeration (dnstwist), MX/SPF/DMARC posture analysis for email-security bypass assessment |

### Priority Targets

- Email servers and webmail portals (Exchange/OWA, Zimbra, Google Workspace login)
- VPN gateways and remote-access portals (GlobalProtect, AnyConnect, FortiVPN)
- DMARC/SPF/DKIM gaps that indicate phishing susceptibility
- Public-facing authentication endpoints without MFA enforcement

---

## FIN7 / Carbanak

**Profile.** Financially motivated (Eastern Europe). Targets retail, hospitality, and restaurant sectors. Known for supply chain reconnaissance, social engineering via fake job offers, and vendor portal exploitation. Extensive use of job-posting analysis to identify technology stacks.

### Known Recon Patterns

- Supply chain mapping: identifying payment processors, POS vendors, and managed-service providers.
- Job posting analysis: extracting technology stacks, internal tooling, and compliance frameworks from ATS platforms.
- Vendor portal discovery: fingerprinting third-party portals that handle payment card data.
- Employee targeting via HR/recruiting workflows (malicious document delivery through job applications).

### Emulation with outrider-recon

| Phase | Skill | Specific Actions |
|-------|-------|-----------------|
| Supply chain | `people-breach-intel` | ATS/job posting analysis (Lever, Greenhouse, Workable), vendor relationship extraction from LinkedIn profiles and press releases |
| Vendor surfaces | `web-surface` | Vendor portal fingerprinting (POS management, payment gateways), third-party login surface enumeration |
| Secret hunting | `secrets-and-dorks` | Package registry scanning (npm, PyPI) for internal package names, Google dorks for exposed PCI-scoped infrastructure |
| Asset discovery | `recon-asset-discovery` | Subdomain enumeration focused on payment-processing subdomains, merchant portal discovery |

### Priority Targets

- Payment processing infrastructure and PCI-scoped surfaces
- POS vendor management portals and update servers
- Supply chain portals (vendor onboarding, EDI/B2B gateways)
- ATS platforms leaking internal technology details

---

## Lazarus Group (DPRK)

**Profile.** State-sponsored (North Korea/RGB). Dual-mission: intelligence collection and revenue generation (cryptocurrency theft). Targets cryptocurrency exchanges, DeFi platforms, and developer supply chains. Known for social engineering developers via fake job offers and trojanized npm/PyPI packages.

### Known Recon Patterns

- Cryptocurrency exchange infrastructure mapping: API endpoints, hot-wallet architectures, custody solutions.
- Developer social engineering: identifying key engineers at crypto firms via LinkedIn and GitHub.
- Supply chain poisoning preparation: npm/PyPI typosquat reconnaissance, dependency confusion targets.
- CI/CD pipeline discovery: identifying build systems, artifact registries, and deployment infrastructure.

### Emulation with outrider-recon

| Phase | Skill | Specific Actions |
|-------|-------|-----------------|
| Developer targeting | `people-breach-intel` | LinkedIn employee enumeration for developer/SRE roles at crypto firms, GitHub contributor profiling |
| Supply chain recon | `secrets-and-dorks` | npm/PyPI typosquat discovery, package registry leak hunting, GitHub code search for internal package names and crypto wallet patterns |
| Identity fabric | `identity-fabric` | Org chart reconstruction for crypto firms, key-person identification (CTO, lead devs, DevOps) |
| Infrastructure | `web-surface` | API endpoint discovery for exchange platforms, CI/CD pipeline surface enumeration (Jenkins, GitLab, GitHub Actions) |
| Crypto-specific | `secrets-and-dorks` | Wallet address patterns in public repos, smart contract deployment keys, RPC endpoint exposure |

### Priority Targets

- Cryptocurrency exchange APIs and hot-wallet infrastructure
- Developer platforms (GitHub orgs, npm scopes, internal package registries)
- CI/CD pipelines (Jenkins, GitLab CI, GitHub Actions with deployment secrets)
- Smart contract deployment infrastructure and admin key surfaces

---

## Generic External Recon Emulation Template

Use this template when emulating any threat actor's external recon phase, or when conducting a general purple-team recon exercise without a specific adversary model.

### Phase 1: Passive Discovery

**Goal.** Build the target's digital footprint without any direct interaction.

| Activity | Skill | ATT&CK Mapping |
|----------|-------|----------------|
| CT log enumeration | `recon-asset-discovery` | T1596.003 |
| Passive DNS collection | `recon-asset-discovery` | T1596.001 |
| WHOIS / reverse WHOIS | `recon-asset-discovery` | T1596.002 |
| Breach data correlation | `people-breach-intel` | T1589.001 |
| Google dorking | `secrets-and-dorks` | T1593.002 |
| Social media profiling | `people-breach-intel` | T1593.001 |
| Scan database queries (Shodan, Censys) | `recon-asset-discovery` | T1596.005 |

### Phase 2: Light Active Probing

**Goal.** Validate passive findings with low-noise active techniques.

| Activity | Skill | ATT&CK Mapping |
|----------|-------|----------------|
| Port scanning (top ports) | `recon-asset-discovery` | T1595.001 |
| Service fingerprinting | `web-surface` | T1595.002 |
| Email security posture (SPF/DMARC/DKIM) | `osint-methodology` | T1598 |
| Technology profiling | `web-surface` | T1592.002 |
| Subdomain validation (DNS resolution) | `recon-asset-discovery` | T1590.002 |

### Phase 3: Targeted Deep-Dive

**Goal.** Focused enumeration against high-value surfaces identified in Phases 1-2.

| Activity | Skill | ATT&CK Mapping |
|----------|-------|----------------|
| Identity fabric enumeration (Entra/Okta/SSO) | `identity-fabric` | T1592.004 |
| Secret hunting (GitHub, registries) | `secrets-and-dorks` | T1593.003 |
| Vendor/technology fingerprinting | `web-surface` | T1592.002 |
| Cloud infrastructure mapping | `cloud-and-infra` | T1590.004 |
| Supply chain / vendor relationship analysis | `people-breach-intel` | T1591.002 |

### Reporting: ATT&CK-Mapped Purple-Team Handoff

Structure the final deliverable for direct purple-team consumption using `analysis-and-reporting`:

1. **Finding inventory** — each finding tagged with ATT&CK technique ID(s) from the table above.
2. **Attack-path narratives** — chain findings into realistic attack paths that a specific (or generic) threat actor would follow.
3. **Detection gap analysis** — for each technique exercised, note whether the target's defensive stack would have observed the recon activity.
4. **Priority matrix** — rank findings by exploitability and threat-actor relevance, referencing the adversary profiles above.

Use `report-template` for the standardized output format and `post-discovery` for finding validation before handoff.

---
