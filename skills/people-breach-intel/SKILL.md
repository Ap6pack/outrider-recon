---
name: people-breach-intel
description: "Breach data lookup, HudsonRock infostealer intel, email-pattern inference, email harvest, Slack/Discord discovery, package registry leaks, and vulnerability prioritization endpoints."
version: 1.0.0
triggers:
  - breach lookup
  - have I been pwned
  - HudsonRock cavalier
  - infostealer
  - dehashed
  - intelx
  - email pattern inference
  - email harvest
  - Slack workspace discovery
  - Discord server discovery
  - npm token leak
  - package registry leaks
---

# People, Breach & Intelligence

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only. Never paste PII or credentials into cloud LLMs.

---

## BEHAVIORAL CONTRACT

**When triggered:** Breach lookups, username/email investigation, HudsonRock/HIBP/DeHashed queries, email-pattern inference, email harvesting, Slack/Discord discovery, or package registry leak hunting is needed.

**Execute:**
1. Run HudsonRock Cavalier domain lookup (§1) as the first call — highest ROI for external engagements.
2. Cross-reference with HIBP and DeHashed for domain-level breach scope.
3. Apply domain-level breach severity mapping (§1): >=10 employees = CRITICAL, 1-9 = HIGH, >=1 end-user = MEDIUM, 0 named = INFO.
4. If SSO tenants discovered (from `identity-fabric`), intersect with breach corpus for SSO_EXPOSURE findings (§1).
5. For each CVE surfaced, apply the 9-Signal Scoring Rubric (§4.1) to assign a priority tier (P0-P3).
6. For known employee names: derive candidate emails using the 8-pattern template (§2), then harvest from 6 parallel sources (§3).
7. Run Slack/Discord workspace discovery dorks (§6).
8. For package registry targets: run historical-version secret scan workflow (§7).
9. For each finding, emit per `osint-methodology` §3 schema.

**Output:** Breach findings, SSO_EXPOSURE findings, person assets with derived emails, email-harvest results — all per `osint-methodology` §3 finding schema.

**Severity rules:** §1 domain-level mapping. SSO_EXPOSURE = CRITICAL. Open Slack invite = HIGH. Package typosquat = MEDIUM.

**Gating rules:** Never paste PII or credentials into cloud LLMs. Encrypt stealer logs at rest. SHA-256 every artifact. Redact passwords in client reports.

**Chain to:** Receive SSO tenant list from `identity-fabric`. Feed validated emails to `identity-fabric` for GetCredentialType probing. Feed breach hits to `osint-methodology` §12 correlation logic. Feed secrets found in package registries to `secrets-and-dorks` for validation.

---

## 1. Breach & Leak Data — Highest ROI Sources

- [Have I Been Pwned](https://haveibeenpwned.com/) — breach lookup; Pwned Passwords API (k-anonymity).
- [Dehashed](https://dehashed.com/) — credential search (paid).
- [IntelX](https://intelx.io/) — data intelligence.
- [LeakCheck](https://leakcheck.io/), [Snusbase](https://snusbase.com/), [BreachDirectory](https://breachdirectory.org/).
- **[Cavalier (Hudson Rock)](https://cavalier.hudsonrock.com/) — infostealer log lookups; FREE; highest single-source ROI for compromised employee credentials.**

### 1.1 HudsonRock Cavalier — Direct API

```bash
# By domain (canonical first call)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=target.com" | jq .

# By email (single-account check)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=alice@target.com" | jq .

# By URL (when target's app is the breach victim)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-url?url=https://app.target.com" | jq .
```

**Top-level JSON fields:**
- `total` — total stealer entries.
- `employees` — count of `<*>@<domain>` accounts found.
- `users` — count of customer accounts where domain appeared as visited URL.
- `data.employees_urls[]` — `{occurrence, type, url}` — **internal apps where employees were logging in when stolen. Subdomain hits here = recon gold.**
- `data.clients_urls[]` — user-facing apps (reveals undocumented portals).
- `data.stealer_families[]` — which stealer (RedLine / Lumma / StealC / Vidar / Raccoon).

**Free-tier caveats:**
- Subdomains past the first few are **redacted with asterisks**. Pivot to paid tier for unredacted.
- Cleartext passwords + emails are **never** in the free response.
- Rate limit ~1 req/sec/IP.

### 1.2 Domain-Level Breach Severity Mapping

| Stat | Severity |
|---|---|
| ≥ 10 employees compromised | **CRITICAL** |
| 1–9 employees compromised | **HIGH** |
| ≥ 1 end-user (non-employee) compromised | **MEDIUM** |
| Domain in breach with 0 named accounts | **INFO** |

### 1.3 SSO_EXPOSURE Finding

When a discovered SSO tenant intersects with the breach corpus → `SSO_EXPOSURE` finding, severity **CRITICAL**.

**Legacy-mail-decommissioned pattern (high-value):**

All three together → CRITICAL `SSO_EXPOSURE`:
1. `Resolve-DnsName mail.<domain> -Type A` → NXDOMAIN (legacy gone)
2. HudsonRock corpus has employee URLs against the old host (e.g., `mail.<domain>/owa/`, `/zimbra/`)
3. Current MX → M365 / Google Workspace (DNS confirms migration)

Evidence pack: tenant GUID + breach count + 3+ legacy URLs + autodiscover Microsoft IPs + current MX. Recommend forced password rotation + MFA audit.

---

## 2. Email-Pattern Inference (TENTATIVE)

Generate 8 candidate addresses for `(first_name, last_name, domain)`:
```
{first}.{last}@{domain}        # john.doe@example.com
{first}{last}@{domain}         # johndoe@example.com
{first}@{domain}               # john@example.com
{first[0]}{last}@{domain}      # jdoe@example.com
{first}.{last[0]}@{domain}     # john.d@example.com
{last}@{domain}                # doe@example.com
{first}_{last}@{domain}        # john_doe@example.com
{first}-{last}@{domain}        # john-doe@example.com
```

Lowercase before lookup. Strip diacritics. If Hunter.io shows a dominant pattern, mark FIRM.

---

## 3. Email-Harvest Source Stack

Six parallel sources — dedup at the end:

1. **IntelX phonebook API** — 2-step search + poll. Largest single source for breach-era addresses.
2. **Hunter.io** — domain-search endpoint. ~25 free/month. Returns verified emails + roles.
3. **crt.sh** — extract X.509 SAN extensions. Many certs include admin/contact emails.
4. **DuckDuckGo SERP scrape** — HTML scrape of `"@{target-domain}"` results.
5. **Bing SERP scrape** — same query, complementary index.
6. **Wayback CDX** — historic snapshots often contain emails removed from the live site.

**Email regex:**
```regex
\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b
```

---

## 4. Vulnerability Prioritization Endpoints

```bash
# EPSS score for a CVE
curl -sk "https://api.first.org/data/v1/epss?cve=CVE-2024-3400" | jq '.data[0]'

# Check if in CISA KEV
curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-3400")'

# InTheWild confirmed-exploitation check
curl -sk "https://inthewild.io/api/vulnerability?cve=CVE-2024-3400"

# Trickest CVE-to-PoC lookup (GitHub repo)
# https://github.com/trickest/cve — browse: /YYYY/CVE-YYYY-NNNNN.md
```

### 4.1 9-Signal Scoring Rubric

Score each CVE additively across nine signals, then map to a priority tier.

**Scoring signals (additive):**

| Signal | Points | Source |
|---|---|---|
| In CISA KEV | +50 | KEV JSON feed |
| EPSS >= 0.7 (top 30%) | +30 | FIRST EPSS API |
| EPSS >= 0.4 (top 50%) | +15 | FIRST EPSS API |
| Metasploit module exists | +20 | rapid7/metasploit-framework GitHub |
| Public PoC on GitHub | +15 | nomi-sec/PoC-in-GitHub or Trickest CVE |
| InTheWild.io confirmed | +20 | inthewild.io/api |
| ExploitDB entry | +10 | exploit-db.com |
| CVSS >= 9.0 | +10 | NVD |
| Vendor advisory confirms active exploitation | +15 | vendor page |

EPSS tiers are mutually exclusive — apply the higher bracket only.

**Priority tiers:**

| Score | Tier | Action |
|---|---|---|
| >= 80 | P0 — Immediate | Flag in exec summary; recommend emergency patch |
| 50-79 | P1 — High | Include in findings; recommend urgent patch |
| 25-49 | P2 — Moderate | Include in findings; recommend scheduled patch |
| < 25 | P3 — Low | Note in appendix; monitor |

---

## 5. ATS URL Patterns

| Platform | URL Pattern |
|---|---|
| Lever (ATS) | `https://jobs.lever.co/<company>` |
| Greenhouse (ATS) | `https://boards.greenhouse.io/<company>` |
| AshbyHQ (ATS) | `https://jobs.ashbyhq.com/<company>` |
| Company careers page | `https://careers.<target>.com` |

---

## 6. Slack / Discord / Telegram Workspace Discovery

**Slack invite-link discovery:**
```
site:join.slack.com "{target}"
inurl:slack.com inurl:shared_invite "{target}"
```
Open invite link = anyone joins without approval → HIGH finding.

**Discord server check:**
```bash
curl -sk "https://discord.com/api/v9/invites/<token>?with_counts=true"
```
Returns server name, ID, member count.

**Mattermost / Rocket.Chat / self-hosted:**
- Look for `chat.<domain>`, `mattermost.<domain>`, `rocket.<domain>` subdomains.
- Mattermost: `GET /api/v4/config/client?format=old` reveals server config if unauthenticated.
- Rocket.Chat: `GET /api/v1/info` returns version + config.
- Public channels may be readable without auth on misconfigured instances.

---

## 7. Package Registry Leak Hunting

### 7.1 npm
```bash
npm search "<target-keyword>"
npm pack <package>@<version>
tar -xzf package-version.tgz
# Run secret catalog over extracted files
```

### 7.2 PyPI
```bash
# Per-package history
curl -sk "https://pypi.org/pypi/<package>/json" | jq '.releases | keys'
pip download <package>==<version> --no-deps -d /tmp/pkg
```

### 7.3 RubyGems
```bash
# Per-gem metadata
curl -sk "https://rubygems.org/api/v1/gems/<gem-name>.json" | jq .
gem fetch <gem-name> && gem unpack <gem-name>-<version>.gem
```

### 7.4 Cargo (Rust crates)
- Search: `https://crates.io/search?q=<target>`
- Per-crate metadata: `https://crates.io/api/v1/crates/<crate-name>`

### 7.5 Packagist (PHP / Composer)
- Search: `https://packagist.org/search/?q=<target>`
- Per-package metadata: `https://packagist.org/packages/<vendor>/<package>.json`

### 7.6 NuGet (.NET)
- Search: `https://www.nuget.org/packages?q=<target>`

### 7.7 Maven Central (Java)
- Search: `https://search.maven.org/?q=<target>`

### 7.8 Workflow

For each candidate package owned by target:
1. List all historical versions (old versions often had leaked keys).
2. Download each version's archive.
3. Extract; run secret catalog.
4. For Docker images: scan each layer with `dive` or `skopeo`.

### 7.9 Typosquat Surveillance

For every published package the target owns, generate typosquat candidates:
```bash
# Example: target package "acme-utils"
for candidate in acme-util acmeutils acme_utils; do
  npm view $candidate 2>&1 | head -3
done
```
Unregistered candidate near target's published package → MEDIUM finding (typosquat / supply-chain risk).
