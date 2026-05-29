# Capabilities

90 capabilities across 15 domains. Categorized by function -- pick a domain to drill in.

---

## Reconnaissance & Asset Discovery

| Capability | Skill |
|---|---|
| 5-stage external recon pipeline + time-budget profiles (1h / 4h / 1d / 1w) | osint-methodology |
| Subdomain-source stack (crt.sh + 7-source fallback chain when crt.sh 502s) | recon-asset-discovery |
| Common-prefix subdomain sweep (119 ordered prefixes, PowerShell + bash) | recon-asset-discovery |
| Wayback CDX deep mining + legacy-app pivot (.asp/.php/.jsp/.cfm) | web-surface |
| WHOIS / RDAP / historical-WHOIS + reverse-WHOIS pivots | recon-asset-discovery |
| Public records (OpenCorporates · SEC EDGAR · GSXT · Rusprofile · Companies House) | docs/reference/tool-directory.md, docs/reference/specialty-domains.md |
| Bulk IP → ASN (Cymru / RIPEstat / bgp.tools) | recon-asset-discovery |

## Identity & SSO Mapping

| Capability | Skill |
|---|---|
| Microsoft Entra (Azure AD) tenant fingerprint + GUID extraction | identity-fabric |
| M365 deep enum (Teams federation · SharePoint · OneDrive · OAuth · device-code phishing) | identity-fabric |
| Autodiscover IP correlation (passive M365 confirm even when MX wrapped by Mimecast/Proofpoint) | identity-fabric |
| Okta tenant slug + `/api/v1/authn` user-enum | identity-fabric |
| ADFS fingerprint + mex endpoint | identity-fabric |
| Google Workspace OIDC discovery | identity-fabric |
| Generic OIDC (Auth0 · Keycloak · Ping · OneLogin · Duo) | identity-fabric |
| SAML metadata (5 paths) | identity-fabric |
| AWS account-ID extraction from headers + ARN regex | identity-fabric |

## Web Application Attack Surface

| Capability | Skill |
|---|---|
| Swagger / OpenAPI discovery (28 paths) | web-surface |
| GraphQL discovery + introspection POST body (13 paths) | web-surface |
| GraphQL field-suggestion enum (when introspection disabled) + alias batching + depth bypass | web-surface |
| Always-on HTTP checks (15 paths: .git/.env/actuator/heapdump/etc.) | web-surface |
| Missing security header audit (HSTS/CSP/XFO/etc.) | web-surface |
| Endpoint extraction regex tiers (3 tiers) | web-surface |
| Endpoint interest score (0-100 rubric) | analysis-and-reporting |
| JS deep analysis · sourcemap leakage · internal-host regex | web-surface |
| Subdomain takeover fingerprints (27 providers) | web-surface |

## Cloud & Container

| Capability | Skill |
|---|---|
| Cloud bucket permutation (S3 / GCS / Azure · 6 prefixes x 15 suffixes x 47 stems) | web-surface |
| Cloud-native fingerprints (Lambda URLs · Cloud Run · Azure Functions · Vercel · Netlify · Workers) | cloud-and-infra |
| Kubernetes / etcd / kubelet exposure (12 ports + probes) | cloud-and-infra |
| Container registry leak hunting (Docker Hub · Quay · GHCR · ECR · GCR · ACR) | cloud-and-infra |
| CI/CD platform exposure (Jenkins · GitLab · TeamCity-KEV · Argo CD · Spinnaker · CircleCI) | cloud-and-infra |

## Secret & Credential Hunting

| Capability | Skill |
|---|---|
| 48-pattern secret-regex catalog (29 base + 19 modern) | secrets-and-dorks |
| Modern AI API keys (Anthropic / OpenAI / HuggingFace / Cloudflare) | secrets-and-dorks |
| Package-registry tokens (npm / PyPI / Docker Hub) | secrets-and-dorks |
| GitHub code-search dorks (13 templates) | secrets-and-dorks |
| 9 read-only credential validators (Postman / AWS / GitHub / Slack / Anthropic / OpenAI / npm / Atlassian / DataDog) | secrets-and-dorks |
| Post-discovery enumeration workflows (IAM enum · repo enum · workspace enum · JWT triage) | post-discovery |
| `secret_scan.py` -- stdlib-only secret scanner (JSONL output) | skills/offensive-osint/scripts |
| `h1_reference.py` -- HackerOne disclosed-reports reference (top-voted / keyword / program filter) | skills/offensive-osint/scripts |
| 70 dork corpus across 9 categories | secrets-and-dorks |

## Breach Intelligence

| Capability | Skill |
|---|---|
| HudsonRock Cavalier direct API (free; FYI: web-UI wraps a public JSON endpoint) | people-breach-intel |
| Domain-level breach severity mapping | people-breach-intel |
| `SSO_EXPOSURE` finding + legacy-mail-decommissioned escalation pattern | people-breach-intel |
| Breach x identity correlation (HudsonRock + HIBP + DeHashed + IntelX) | osint-methodology |

## Vendor & Edge-Appliance Fingerprinting

| Capability | Skill |
|---|---|
| Citrix Netscaler · F5 BIG-IP · Pulse Secure / Ivanti · FortiGate | web-surface |
| PaloAlto GlobalProtect · Cisco AnyConnect · VMware vCenter / ESXi / Horizon | web-surface |
| Microsoft Exchange OWA (ProxyShell / ProxyLogon / ProxyNotShell) | web-surface |
| KEV CVE enrichment + EPSS scoring + Metasploit availability | people-breach-intel |
| WAF / CDN bypass + origin discovery (8 techniques) | docs/methods/cdn-bypass-techniques.md |

## Email Security

| Capability | Skill |
|---|---|
| SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT / DNSSEC audit (bash + PowerShell) | web-surface |
| DMARC reporting-vendor inference (Kratikal / dmarcian / Valimail / Agari / EasyDMARC) | web-surface |
| TXT verification token catalog (35 SaaS tenants) | recon-asset-discovery |
| MX → IdP / mail-host inference | web-surface |

## Human Intelligence

| Capability | Skill |
|---|---|
| LinkedIn employee enumeration (P0-P5 role tiers · sock-puppet hygiene) | identity-fabric |
| Job posting tech-stack analysis (Lever · Greenhouse · AshbyHQ) | people-breach-intel |
| Slack / Discord / Telegram / Mattermost workspace discovery | people-breach-intel |
| Sat imagery for physical recon (Google Earth · NearMap · Sentinel Hub) | docs/reference/tool-directory.md |
| Email-pattern inference (8 templates) | people-breach-intel |

## Supply Chain

| Capability | Skill |
|---|---|
| Package-registry leak hunting (npm · PyPI · RubyGems · Cargo · Packagist · NuGet · Maven) | people-breach-intel |
| Typosquat surveillance | people-breach-intel |
| Postman public-workspace search (verified endpoint) | web-surface |
| Stack Exchange OSINT sweep (8 sites) | web-surface |

## Reporting & Deliverables

| Capability | Skill |
|---|---|
| Findings rubric (CRITICAL/HIGH/MED/LOW/INFO + escalation) | osint-methodology |
| Severity decision matrix (92 worked examples) | analysis-and-reporting |
| Attack-path hint patterns (35 templates) | analysis-and-reporting |
| Bug-bounty submission templates (HackerOne / Bugcrowd / Intigriti) | osint-methodology |
| Client deliverable templates (exec summary · risk-translation matrix · cadence) | osint-methodology |
| Reproduction package | osint-methodology |

## Sector-Specific

| Capability | Skill |
|---|---|
| Healthcare (DICOM · HL7 v2 · FHIR · Epic / Cerner / Allscripts) | analysis-and-reporting, docs/reference/specialty-domains.md |
| Finance (SWIFT · FIX · Bloomberg · Temenos / Finacle / FIS / Fiserv) | analysis-and-reporting, docs/reference/specialty-domains.md |
| ICS / SCADA (Modbus · BACnet · Siemens S7 · DNP3 · EtherNet/IP) | analysis-and-reporting, docs/reference/specialty-domains.md |
| IoT (MQTT · CoAP · UPnP · Hikvision / Dahua DVRs) | analysis-and-reporting, docs/reference/specialty-domains.md |
| Government (`.gov` / `.mil` · FedRAMP · FISMA · CUI · SAM.gov) | analysis-and-reporting, docs/reference/specialty-domains.md |

## Continuous Monitoring and Engagement Ops

| Capability | Skill |
|---|---|
| Daily subdomain/DNS/cert diff pipeline with Slack alerting | docs/methods/continuous-monitoring.md |
| Weekly deep scan orchestration (Nuclei + port diff + Wayback) | docs/methods/continuous-monitoring.md |
| False-positive suppression and tuning framework | docs/methods/continuous-monitoring.md |
| Multi-tenant engagement isolation (scope, credentials, output) | docs/methods/multi-tenant-workflow.md |
| Parallel execution patterns (GNU parallel, Axiom fleet) | docs/methods/multi-tenant-workflow.md |
| Engagement decommission and evidence destruction workflow | docs/methods/multi-tenant-workflow.md |
| Burp Suite engagement config + recon extensions | docs/methods/burp-zap-setup.md |
| OWASP ZAP automation framework YAML recipes | docs/methods/burp-zap-setup.md |
| Proxy traffic tagging for bug bounty compliance | docs/methods/burp-zap-setup.md |

## Tool Integration and Workflows

| Capability | Skill |
|---|---|
| Recon-ng module walkthrough (7 key modules) | docs/methods/tool-chaining-recipes.md |
| SpiderFoot scan profiles and CLI recipes | docs/methods/tool-chaining-recipes.md |
| Maltego transforms for external recon | docs/methods/tool-chaining-recipes.md |
| Bash-native multi-tool pipelines (subfinder/httpx/nuclei/jq) | docs/methods/tool-chaining-recipes.md |
| OPSEC infrastructure provisioning (Terraform/Ansible) | docs/methods/opsec-infrastructure.md |
| IP rotation and proxy chaining patterns | docs/methods/opsec-infrastructure.md |
| Adversary-emulation playbooks (APT29/APT28/FIN7/Lazarus) | docs/reference/adversary-emulation.md |
| Report customization and delivery formats | docs/methods/report-customization.md |
| Tool failure recovery and fallback chains | docs/methods/tool-failure-recovery.md |

> Diagrams: see [`architecture.md`](architecture.md) for the Capability Map, Engagement Flow, and 7 other Mermaid diagrams.
