---
name: recon-asset-discovery
description: "Subdomain enumeration, CT logs, DNS record catalog, WHOIS/RDAP, and passive reconnaissance for authorized external recon."
version: 1.0.0
triggers:
  - subdomain enumeration
  - asset discovery
  - certificate transparency
  - crt.sh
  - WHOIS lookup
  - RDAP
  - DNS record catalog
  - passive recon
  - footprinting
---

# Recon — Asset Discovery

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** Subdomain enumeration, asset discovery, DNS records, CT logs, WHOIS/RDAP, or passive reconnaissance is needed.

**Execute:**
1. Run the passive subdomain-source stack (§1) in parallel across all listed sources. If crt.sh is down, follow the fallback chain.
2. Complement passive results with common-prefix candidates from the prefix wordlist (§2).
3. Run WHOIS/RDAP (§3) on the root domain. Extract registrant org/email for pivoting.
4. Catalog DNS records (§4) for every discovered domain/subdomain. Parse TXT records for SaaS tenancy inference using the verification token table.
5. Check autodiscover for M365 confirmation (§4).
6. Deduplicate all discovered assets by typed key. Tag each with confidence level per `osint-methodology` §2.

**Output:** Asset list with typed keys (subdomain, ip, domain) per `osint-methodology` §8 taxonomy.

**Severity rules:** DNS AXFR success = CRITICAL. Missing CAA = LOW.

**Gating rules:** Passive first. Active prefix sweep only when authorized. Brute-force (puredns) only with explicit operator approval.

**Chain to:** Feed discovered subdomains to `web-surface` for probing. Feed discovered emails to `people-breach-intel` for breach lookup. Feed discovered IPs to `cloud-and-infra` for infrastructure analysis.

---

## 1. Subdomain-Source Stack (Passive)

| Source | Tier | Notes |
|---|---|---|
| crt.sh | Free | Best single source; **frequently 502s — see fallback chain** |
| VirusTotal | Freemium | Domain → passive DNS history |
| AlienVault OTX | Free | Passive DNS + URL data |
| Shodan | Paid (low tier) | Subdomain enum via `domain:` filter |
| SecurityTrails | Paid | Passive DNS + asset discovery |
| RapidDNS | Free | Public passive DNS |
| Subfinder | Free | Aggregates 30+ free sources |
| Amass | Free | Thorough, slower |
| Recon-ng | Free | Modular framework |

**DNS AXFR opportunism:**
```
dig @<ns-host> <target-domain> AXFR
```
Most NSs reject; those that don't = full zone disclosure (CRITICAL).

**Brute-force tier:** puredns against [assetnote.io](https://wordlists.assetnote.io/) wordlists.

### 1.1 crt.sh Down? Fallback Chain

```bash
D="target.example"

# 1. Censys cert search (free 250 queries/month with key)
censys search "names: ${D}" --index-type certificates --fields names | jq -r '.names[]' | sort -u

# 2. Cert Spotter API (sslmate) — free w/ rate limits
curl -sk "https://api.certspotter.com/v1/issuances?domain=${D}&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sort -u

# 3. CertStream archive (Calidog)
curl -sk "https://crt.calidog.io/?q=${D}" | jq -r '.[].name_value' | sort -u

# 4. Subfinder bundled aggregator (30+ sources)
subfinder -d ${D} -all -recursive -silent

# 5. AlienVault OTX — free, no key
curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${D}/passive_dns" | \
  jq -r '.passive_dns[].hostname' | sort -u

# 6. ThreatMiner
curl -sk "https://api.threatminer.org/v2/domain.php?q=${D}&rt=5" | jq -r '.results[]'

# 7. URLScan
curl -sk "https://urlscan.io/api/v1/search/?q=domain:${D}" | \
  jq -r '.results[].page.domain' | sort -u

# 8. Anubis-DB (last resort)
curl -sk -A "Mozilla/5.0" "https://anubisdb.com/anubis/subdomains/${D}" | jq -r '.[]'
```

---

## 2. Common-Prefix Wordlist

119 prefixes. Passive enum misses 20-40% of high-value subdomains. Pair with active prefix probe when authorized (detectability: low -- single A-record query per host).

```
www mail webmail owa autodiscover ftp vpn sslvpn gateway api app portal
login sso idp iam identity accounts oauth auth adfs admin intranet hr
sap erp crm support help status grafana kibana docs wiki jira jenkins
gitlab dev test staging stg qa uat sandbox preprod preview careers jobs
eapps old legacy beta tender suppliers procurement
cdn static img images assets media files download upload search shop
store pay payment billing invoice ticket board chat meet video webinar
register signup sso-proxy proxy relay bounce mx smtp imap pop
ns1 ns2 ns3 dns ntp ldap radius vpn2 remote rdp citrix bastion jump
db mysql postgres redis mongo elastic kafka rabbit queue worker cron
monitor prometheus alertmanager vault consul log syslog splunk
```

### 2.1 Wordlist Sources

| Source | URL | Notes |
|---|---|---|
| **Assetnote Wordlists** | `https://wordlists.assetnote.io/` | Best-curated; updated regularly |
| **SecLists** | `https://github.com/danielmiessler/SecLists` | Subdomains: `Discovery/DNS/subdomains-top1million-110000.txt` |
| **jhaddix all.txt** | `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056` | Long-running curated |
| **OneListForAll** | `https://github.com/six2dez/OneListForAll` | Aggregated; very large |
| **raft-large-words.txt** | inside SecLists | Time-tested content wordlist |
| **commonspeak2** | `https://github.com/assetnote/commonspeak2-wordlists` | Generated from BigQuery |
| **fuzzdb** | `https://github.com/fuzzdb-project/fuzzdb` | Fuzzing payloads + wordlists |

**Size guidance:**

| Wordlist size | Speed class | Typical runtime | Use case |
|---|---|---|---|
| <10k entries | Fast | 1–2 min | Quick validation, CI/CD gates |
| 10k–100k entries | Standard | 10–30 min | Standard engagement recon |
| 100k–1M entries | Thorough | 1–4 hours | Full-scope pentest |
| >1M entries | Exhaustive | Multi-day | Week-long engagements, red team ops |

---

## 3. WHOIS / RDAP

```bash
whois target.example
curl -sk "https://rdap.org/domain/${D}" | jq .
```

What to extract: registrant org/email, registrar (pivot for related domains), created/updated dates (bulk registration patterns), nameservers (NS reuse pivot), status flags.

**Historical WHOIS:** Services like WhoisXMLAPI, SecurityTrails, and DomainTools archive past WHOIS snapshots. Historical records reveal previous registrant info hidden by current privacy services, ownership transfers, and infrastructure changes.

```bash
# SecurityTrails historical WHOIS (API key required)
curl -sk "https://api.securitytrails.com/v1/history/${D}/whois" -H "APIKEY: ${ST_KEY}" | jq '.result[] | {date: .first_seen, registrant: .registrant}'
```

**Reverse WHOIS:** Pivot from a known registrant name, email, or org to discover all domains they own:
- WhoisXMLAPI reverse WHOIS: search by registrant email or org name
- DomainTools reverse WHOIS: same capability, different corpus
- SecurityTrails: `GET /v1/domain/search?filter[whois_email]={email}`

This is a high-value pivot — a single registrant email can reveal dozens of related domains not discoverable through DNS or CT alone.

---

## 4. DNS Record Catalog

```bash
D="target.example"
for rtype in A AAAA MX TXT NS SOA CAA SRV CNAME PTR; do
  echo "=== ${rtype} ===" && dig +short "${D}" "${rtype}"
done
```

**TXT verification tokens → SaaS tenancy inference (35 patterns):**

| TXT pattern | SaaS / service |
|---|---|
| `google-site-verification=<token>` | Google Workspace |
| `MS=ms<digits>` | Microsoft 365 |
| `adobe-idp-site-verification=<token>` | Adobe |
| `amazonses:<token>` | AWS SES (alternate form) |
| `_amazonses=<token>` | AWS SES |
| `apple-domain-verification=<token>` | Apple |
| `atlassian-domain-verification=<token>` | Atlassian Cloud |
| `calendly-site-verification=<token>` | Calendly |
| `cisco-ci-domain-verification=<token>` | Cisco Webex |
| `citrix-verification-code=<token>` | Citrix |
| `docker-verification=<token>` | Docker |
| `docusign=<token>` | DocuSign |
| `facebook-domain-verification=<token>` | Facebook / Meta |
| `github-verification=<token>` | GitHub |
| `gitlab-domain-verification=<token>` | GitLab |
| `hubspot-developer-verification=<token>` | HubSpot (developer) |
| `hubspot-domain-verification=<token>` | HubSpot CRM |
| `intercom-verification=<token>` | Intercom |
| `logmein-verification-code=<token>` | LogMeIn / GoTo |
| `miro-verification=<token>` | Miro |
| `onetrust-domain-verification=<token>` | OneTrust |
| `pinterest-site-verification=<token>` | Pinterest |
| `salesforce-domain-verification=<token>` | Salesforce |
| `slack-domain-verification=<token>` | Slack Enterprise Grid |
| `smartsheet-site-validation=<token>` | Smartsheet |
| `sophos-domain-verification=<token>` | Sophos |
| `status-page-domain-verification=<token>` | Statuspage / Atlassian |
| `stripe-verification=<token>` | Stripe |
| `teamviewer-sso-verification=<token>` | TeamViewer |
| `twilio-domain-verification=<token>` | Twilio |
| `workday-domain-verification=<token>` | Workday (HR + Finance) |
| `yandex-verification:<token>` | Yandex |
| `zoho-verification=<token>` | Zoho |
| `zoom_verify_<id>` | Zoom |
| `zscaler-verification-<id>-<date>-<random>` | Zscaler (ZIA/ZPA/ZDX) |

Each discovered tenancy is a separate attack surface (own credentials, own MFA posture).

**Autodiscover-as-M365-confirmation:**
```bash
dig +short A "autodiscover.target.example"
```
If IP lands in `40.96.0.0/13`, `52.96.0.0/14`, `13.107.0.0/16` → `M365_CONFIRMED` even when MX is wrapped by Mimecast/Proofpoint.

**CAA records (cert issuance control):**
```bash
dig +short CAA "${D}"
```
Absence = LOW (any CA can mis-issue). Presence + restrictive list = good posture.
