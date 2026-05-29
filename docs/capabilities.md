# Capabilities

90+ capabilities across 12 domains. Categorized by function — pick a domain to drill in.

---

## Reconnaissance & Asset Discovery

| Capability | Skill |
|---|---|
| 5-stage external recon pipeline + time-budget profiles (1h / 4h / 1d / 1w) | methodology |
| Subdomain-source stack (crt.sh + 7-source fallback chain when crt.sh 502s) | arsenal |
| Common-prefix subdomain sweep (100+ ordered prefixes, PowerShell + bash) | arsenal |
| Wayback CDX deep mining + legacy-app pivot (.asp/.php/.jsp/.cfm) | arsenal |
| WHOIS / RDAP / historical-WHOIS + reverse-WHOIS pivots | arsenal |
| Public records (OpenCorporates · SEC EDGAR · GSXT · Rusprofile · Companies House) | arsenal |
| Bulk IP → ASN (Cymru / RIPEstat / bgp.tools) | arsenal |

## Identity & SSO Mapping

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

## Web Application Attack Surface

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

## Cloud & Container

| Capability | Skill |
|---|---|
| Cloud bucket arsenal (S3 / GCS / Azure · 6 prefixes × 15 suffixes × 47 stems) | arsenal |
| Cloud-native fingerprints (Lambda URLs · Cloud Run · Azure Functions · Vercel · Netlify · Workers) | arsenal |
| Kubernetes / etcd / kubelet exposure (12 ports + probes) | arsenal |
| Container registry leak hunting (Docker Hub · Quay · GHCR · ECR · GCR · ACR) | arsenal |
| CI/CD platform exposure (Jenkins · GitLab · TeamCity-KEV · Argo CD · Spinnaker · CircleCI) | arsenal |

## Secret & Credential Hunting

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

## Breach Intelligence

| Capability | Skill |
|---|---|
| HudsonRock Cavalier direct API (free; FYI: web-UI wraps a public JSON endpoint) | arsenal |
| Domain-level breach severity mapping | arsenal |
| `SSO_EXPOSURE` finding + legacy-mail-decommissioned escalation pattern | arsenal |
| Breach × identity correlation (HudsonRock + HIBP + DeHashed + IntelX) | methodology |

## Vendor & Edge-Appliance Fingerprinting

| Capability | Skill |
|---|---|
| Citrix Netscaler · F5 BIG-IP · Pulse Secure / Ivanti · FortiGate | arsenal |
| PaloAlto GlobalProtect · Cisco AnyConnect · VMware vCenter / ESXi / Horizon | arsenal |
| Microsoft Exchange OWA (ProxyShell / ProxyLogon / ProxyNotShell) | arsenal |
| KEV CVE enrichment + EPSS scoring + Metasploit availability | arsenal |
| WAF / CDN bypass + origin discovery (8 techniques) | methodology, arsenal |

## Email Security

| Capability | Skill |
|---|---|
| SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT / DNSSEC audit (bash + PowerShell) | arsenal |
| DMARC reporting-vendor inference (Kratikal / dmarcian / Valimail / Agari / EasyDMARC) | arsenal |
| TXT verification token catalog (35+ SaaS tenants) | arsenal |
| MX → IdP / mail-host inference | arsenal |

## Human Intelligence

| Capability | Skill |
|---|---|
| LinkedIn employee enumeration (P0–P5 role tiers · sock-puppet hygiene) | arsenal |
| Job posting tech-stack analysis (Lever · Greenhouse · AshbyHQ · Workable) | arsenal |
| Slack / Discord / Telegram / Mattermost workspace discovery | arsenal |
| Sat imagery for physical recon (Google Earth · NearMap · Sentinel Hub) | arsenal |
| Email-pattern inference (8 templates) | arsenal |

## Supply Chain

| Capability | Skill |
|---|---|
| Package-registry leak hunting (npm · PyPI · RubyGems · Cargo · Packagist · NuGet · Maven) | arsenal |
| Typosquat surveillance | arsenal |
| Postman public-workspace search (verified endpoint) | arsenal |
| Stack Exchange OSINT sweep (8 sites) | arsenal |

## Reporting & Deliverables

| Capability | Skill |
|---|---|
| Findings rubric (CRITICAL/HIGH/MED/LOW/INFO + escalation) | methodology |
| Severity decision matrix (92 worked examples) | arsenal |
| Attack-path hint patterns (35 templates) | arsenal |
| Bug-bounty submission templates (HackerOne / Bugcrowd / Intigriti) | methodology |
| Client deliverable templates (exec summary · risk-translation matrix · cadence) | methodology |
| Reproduction package | methodology |

## Sector-Specific

| Capability | Skill |
|---|---|
| Healthcare (DICOM · HL7 v2 · FHIR · Epic / Cerner / Allscripts) | arsenal |
| Finance (SWIFT · FIX · Bloomberg · Temenos / Finacle / FIS / Fiserv) | arsenal |
| ICS / SCADA (Modbus · BACnet · Siemens S7 · DNP3 · EtherNet/IP) | arsenal |
| IoT (MQTT · CoAP · UPnP · Hikvision / Dahua DVRs) | arsenal |
| Government (`.gov` / `.mil` · FedRAMP · FISMA · CUI · SAM.gov) | arsenal |


> Diagrams: see [`architecture.md`](architecture.md) for the Capability Map, Engagement Flow, and 7 other Mermaid diagrams.
