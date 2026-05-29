---
name: web-surface
description: "Probe paths, endpoint scoring, email security analysis, vendor fingerprints, documentation leak hunting, and API endpoint references for authorized web-surface enumeration."
version: 1.0.0
triggers:
  - swagger discovery
  - openapi discovery
  - graphql introspection
  - endpoint enumeration
  - email security analysis
  - SPF DMARC DKIM
  - BIMI
  - MTA-STS
  - TLS-RPT
  - DNSSEC
  - MX inference
  - DMARC vendor
  - vendor product fingerprints
  - Citrix Netscaler
  - F5 BIG-IP
  - Pulse Secure
  - FortiGate
  - PaloAlto GlobalProtect
  - Cisco AnyConnect
  - VMware vCenter
  - Wayback CDX
  - postman workspace
  - stack exchange OSINT
  - subdomain takeover
  - documentation leak
---

# Web Surface Enumeration

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** Web surface enumeration, Swagger/OpenAPI/GraphQL discovery, endpoint probing, email security analysis, vendor fingerprinting, documentation leak hunting, or subdomain takeover assessment is needed.

**Execute:**
1. For each alive webapp, probe the Swagger/OpenAPI paths (§1) and GraphQL paths (§2).
2. Check high-risk ports (§3) against Shodan/naabu results.
3. Audit security headers (§4) — escalate per sensitive-path rules.
4. Run always-on HTTP checks (§5) with listed match logic.
5. Probe JS guess-paths (§6) and extract endpoints via regex tiers (§7).
6. Check for internal-host leakage (§8) in JS bodies, sourcesContent, APK strings.
7. Audit email security posture (§9): parse SPF/DMARC/DKIM/BIMI/MTA-STS/TLS-RPT/DNSSEC, map severity, infer SaaS tenants from TXT records, extract DMARC vendor and MX-based IdP.
8. Fingerprint vendor products (§10) — cross-reference with CISA KEV for severity escalation.
9. Assess subdomain takeover risk (§11) using provider fingerprints.
10. Enumerate cloud buckets (§12) using permutation arsenal.
11. Check documentation/wiki leak paths (§13).
12. Query API endpoints (§14) for Wayback CDX, Postman workspace search, and Stack Exchange OSINT.
13. For each finding, assign severity per the inline tables and emit per `osint-methodology` §3 schema.

**Output:** Per-finding results using `osint-methodology` §3 schema.

**Severity rules:** Swagger/OpenAPI without auth = HIGH. GraphQL introspection without auth = HIGH. Vendor product matching KEV CVE = CRITICAL. Missing HSTS on login page = HIGH (escalated from MEDIUM).

**Gating rules:** Authorized targets only. Detection-aware: if 429s or WAF blocks appear during probing, follow `osint-methodology` §6.4 back-off ladder.

**Chain to:** Load `secrets-and-dorks` for secret scanning of discovered JS/API specs. Load `analysis-and-reporting` for endpoint interest scoring (score >= 70 gets attack-path hint). Feed discovered email security gaps to `people-breach-intel`.

---

## 1. Swagger / OpenAPI Discovery — 28 Paths

Probe each on every alive webapp. GET (or HEAD if rate-limited).

```
swagger.json           swagger.yaml
swagger/v1/swagger.json    swagger/v2/swagger.json
swagger-ui.html        swagger-ui/
swagger-resources      api-docs
api-docs.json          api/swagger
api/swagger.json       api/swagger-ui.html
api/v1/swagger.json    api/v2/swagger.json
api/v3/api-docs        v2/api-docs
v3/api-docs            openapi.json
openapi.yaml           openapi/v1
openapi/v3             docs
redoc                  rapidoc
api/docs               api/documentation
api/swagger.yaml       .well-known/openapi
```

Reachable Swagger/OpenAPI spec without auth → **HIGH** `LEAKY_API_SPEC`.

---

## 2. GraphQL Discovery — 13 Paths

```
graphql    graphiql    api/graphql    v1/graphql    v2/graphql
query      api/query   gql            altair
playground subscriptions graphql/console api/v1/graphql
```

**Standard introspection POST body:**
```json
{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } queryType { name } mutationType { name } subscriptionType { name } } }"}
```

- Introspection without auth → **HIGH** `OPEN_GRAPHQL_API`.
- Field-suggestion enumeration (server "did you mean" on typo'd fields) → MEDIUM (re-derive partial schema even when introspection is disabled).
- Batched queries (`[...]` request body) → MEDIUM (rate-limit bypass).

---

## 3. High-Risk Ports — Selected (35 total)

| Port | Service | Severity | Why it matters |
|---|---|---|---|
| 445 | SMB | **CRITICAL** | EternalBlue, SMB relay |
| 2375 | Docker API (unencrypted) | **CRITICAL** | Unauthenticated container takeover |
| 3389 | RDP | **CRITICAL** | BlueKeep / DejaBlue |
| 6379 | Redis | **CRITICAL** | No auth default; write authorized_keys |
| 9200 | Elasticsearch | **CRITICAL** | Typically no auth |
| 27017 | MongoDB | **CRITICAL** | No auth by default |
| 22 | SSH | LOW | Banner; brute-force surface |
| 161 | SNMP | HIGH | Community strings; full device enum |
| 389 | LDAP | HIGH | Anonymous bind = full directory dump |
| 1433 | MSSQL | HIGH | Brute-force; xp_cmdshell |
| 2049 | NFS | HIGH | World-readable exports |
| 5432 | PostgreSQL | HIGH | Brute-force; default postgres:postgres |
| 5601 | Kibana | HIGH | Often unauthenticated |
| 8888 | Jupyter | HIGH | Interactive shell |

---

## 4. Missing Security Headers — 6 Findings

| Header | Severity (default) | Severity (sensitive path) |
|---|---|---|
| `Strict-Transport-Security` | MEDIUM | **HIGH** (for /login, /admin, /sso) |
| `Content-Security-Policy` | MEDIUM | MEDIUM |
| `X-Frame-Options` | LOW | LOW |
| `X-Content-Type-Options` | LOW | LOW |
| `Referrer-Policy` | INFO | INFO |
| `Permissions-Policy` | INFO | INFO |

---

## 5. Always-On HTTP Checks — 15 Paths

| Path | Finding | Severity | Match logic |
|---|---|---|---|
| `/.git/config` | Exposed `.git` | **CRITICAL** | Body contains `[core]`, `repositoryformatversion` |
| `/.env` | Exposed `.env` | **CRITICAL** | `^\s*[A-Z_][A-Z0-9_]*\s*=` |
| `/actuator/env` | Spring Boot env | **CRITICAL** | `"propertySources"` |
| `/actuator/heapdump` | Spring Boot heap | **CRITICAL** | HPROF bytes / large binary |
| `/_cat/indices` | Elasticsearch open | HIGH | Returns index list |
| `/phpinfo.php` | phpinfo() leak | HIGH | `phpinfo()`, `PHP Version` |
| `/console` | Jenkins console | HIGH | `Jenkins`/`Script Console` |
| `/manager/html` | Tomcat Manager | HIGH | `Tomcat Web Application Manager` |
| `/.git/HEAD` | Exposed HEAD | HIGH | Body matches `^ref:\s` |
| `/server-status` | Apache status | MEDIUM | `Apache Server Status` |
| `/server-info` | Apache info | MEDIUM | `Apache Server Information` |
| `/info.php` | phpinfo (alt) | HIGH | Same as phpinfo.php |
| `/.DS_Store` | DS_Store | LOW | Byte signature `\x00\x00\x00\x01Bud1` |
| `/wp-admin/install.php` | WP orphan install | LOW | `WordPress Installation` |
| `/.well-known/security.txt` | Disclosure policy | INFO | Parse contact + policy |

Also parse `/robots.txt` `Disallow:` paths as next-tier wordlist.

---

## 6. JS Guess-Paths for Endpoint Discovery

Probe on every alive webapp (in addition to scraped `<script src=...>`):

```
/main.js
/app.js
/bundle.js
/runtime.js
/index.js
/vendor.js
/_next/static/_buildManifest.js
/_next/static/_ssgManifest.js
/static/js/main.js
/static/js/bundle.js
/assets/index.js
```

For every found JS, also try `<jsfile>.map` for sourcemap leaks (HIGH `INFO_DISCLOSURE`).

---

## 7. Endpoint Extraction Regex Tiers

Three tiers, run in order on every JS body + every sourcesContent[] blob:

**Tier 1 — generic quoted paths:**
```regex
['"`](/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]
```

**Tier 2 — API-ish paths:**
```regex
['"`](/(?:api|graphql|gql|v\d+|swagger|openapi|rest|services|internal|admin|auth|oauth|user|users|account|accounts|search|export|upload|file|files|download|webhook|hooks|callback|admin)/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]
```

**Tier 3 — fully-qualified URLs:**
```regex
\bhttps?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?::\d+)?[/A-Za-z0-9_\-./{}\[\]?=&%:#]*
```

Dedup on `(method, normalized-path-template)` where the template replaces `/123/` with `/{id}/`.

---

## 8. Internal-Host Leakage Regexes

Run on every JS body + sourcesContent + APK strings + manifest:

**RFC1918:**
```regex
\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|127\.(?:\d{1,3}\.){2}\d{1,3})\b
```

**Internal DNS suffixes:**
```regex
\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:internal|corp|lan|intranet|local|prod|staging|dev|qa|test)\b
```

**Kubernetes service DNS:**
```regex
\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b
```

Each match → MEDIUM `INFO_DISCLOSURE`. Aggregate per host: if many matches share the same internal subdomain, that's a recon seed for any future internal phase.

---

## 9. Email Security Analysis (SPF/DMARC/DKIM/BIMI/MTA-STS)

```bash
D="target.example"
dig +short TXT "$D" | grep -i 'v=spf1'
dig +short TXT "_dmarc.${D}"
dig +short MX "${D}"
```

**SPF parsing:** `-all` = strict; `~all` = softfail (spoofs land in spam); `?all` = permissive.
SPF `include:` reveals SaaS tenants: `_spf.google.com` → Google Workspace; `spf.protection.outlook.com` → M365; `sendgrid.net` → SendGrid; `_spf.atlassian.net` → Atlassian Cloud.

**DMARC severity:** `p=none` → MEDIUM; `p=quarantine pct<100` → LOW; `p=reject` + strict alignment → no finding.

**DMARC reporting-vendor inference:** When the DMARC record contains `rua=` or `ruf=` mailto addresses, the reporting vendor can be inferred from the domain:

| Vendor domain | Vendor |
|---|---|
| `kratikal.com` | Kratikal |
| `dmarcian.com` | dmarcian |
| `valimail.com` | Valimail |
| `agari.com` | Agari (now HelpSystems) |
| `easydmarc.com` | EasyDMARC |
| `proofpoint.com` | Proofpoint |
| `mimecast.com` | Mimecast |
| `barracuda.com` | Barracuda |

```bash
dig +short TXT "_dmarc.${D}" | grep -oP 'rua=mailto:\K[^;]+'
```

This is INFO-level intel, not a finding — it reveals the target's email security vendor stack.

**DKIM common selectors:**
```bash
for selector in default google selector1 selector2 mail email k1 dkim s1 s2 amazonses 20240101 mailchimp sendgrid mxvault; do
  dig +short TXT "${selector}._domainkey.${D}"
done
```

**BIMI check:** BIMI presence signals mature email auth (SPF + DMARC + DKIM all enforced).
```bash
dig +short TXT "default._bimi.${D}"
# Expect: v=BIMI1; l=<logo-URL>; a=<VMC-URL>
```
Present → no finding. Absent → INFO only.

**MTA-STS check:** Controls whether sending MTAs must use TLS for delivery.
```bash
dig +short TXT "_mta-sts.${D}"
curl -sS "https://mta-sts.${D}/.well-known/mta-sts.txt"
# Look for mode: enforce | testing | none
```
`mode: enforce` → no finding. `mode: testing` → INFO. Absent with MX records present → LOW.

**TLS-RPT check:** Complements MTA-STS with TLS failure reporting.
```bash
dig +short TXT "_smtp._tls.${D}"
# Expect: v=TLSRPTv1; rua=mailto:<reporting-addr>
```
Absent → INFO (complementary to MTA-STS).

**DNSSEC check:** Validates DNS responses are signed.
```bash
dig +dnssec "${D}" SOA +short
# Look for RRSIG record in response
dig "${D}" SOA +dnssec | grep -c 'RRSIG'
```
DNSSEC signed (RRSIG present) → no finding. Not signed → INFO.

**PowerShell parallel:**
```powershell
$D = "target.example"
"=== SPF ==="; (Resolve-DnsName $D -Type TXT -EA SilentlyContinue | ? { $_.Strings -match 'v=spf1' }).Strings
"=== DMARC ==="; (Resolve-DnsName "_dmarc.$D" -Type TXT -EA SilentlyContinue).Strings
"=== MX ==="; Resolve-DnsName $D -Type MX -EA SilentlyContinue | Select NameExchange,Preference
```

**MX-to-IdP / mail-host inference:** MX records reveal the email hosting provider, which often implies the identity provider.

```bash
dig +short MX "${D}" | sort -n
```

| MX pattern | Provider |
|---|---|
| `aspmx.l.google.com` | Google Workspace |
| `*.mail.protection.outlook.com` | Microsoft 365 |
| `*.pphosted.com` | Proofpoint (often fronting M365/GWS) |
| `*.mimecast.com` | Mimecast |
| `mx*.zoho.com` | Zoho Mail |
| `*.messagelabs.com` | Broadcom/Symantec |

Cross-reference: if MX → M365, load `identity-fabric` for Entra enum. If MX → Google, check Google Workspace OIDC. Severity: INFO (infrastructure intel, not a finding).

---

## 10. Vendor Product Fingerprints

| Product | Fingerprint paths | KEV CVEs |
|---|---|---|
| **Citrix Netscaler** | `/vpn/index.html`, `/logon/LogonPoint/tmindex.html` | CVE-2023-3519, CVE-2019-19781 |
| **F5 BIG-IP TMUI** | `/tmui/login.jsp`, `/mgmt/tm/sys/` | CVE-2022-1388, CVE-2023-46747 |
| **Cisco AnyConnect** | `/+CSCOE+/`, `/CSCOE/index.html`, `/webvpn.html` | CVE-2020-3452 |
| **Pulse Secure / Ivanti** | `/dana-na/auth/url_default/welcome.cgi` | CVE-2024-21887, CVE-2023-46805 |
| **FortiGate** | `/remote/login`, `/remote/info`, `/api/v2/` | CVE-2022-42475, CVE-2024-21762 |
| **PaloAlto GlobalProtect** | `/global-protect/`, `/api/?type=keygen` | CVE-2024-3400 |
| **VMware vCenter** | `/sdk`, `/vsphere-client/`, `/websso/SAML2/` | CVE-2021-21972, CVE-2021-22005 |
| **MS Exchange OWA** | `/owa/`, `/ews/exchange.asmx`, `/ecp/` | ProxyShell, ProxyLogon, ProxyNotShell |
| **Atlassian Confluence** | `/confluence/`, `/login.action` | CVE-2022-26134, CVE-2023-22515 |
| **GitLab self-hosted** | `/users/sign_in`, `/help` | CVE-2021-22205 |
| **TeamCity** | `/login.html` | CVE-2024-27198 |
| **ConnectWise ScreenConnect** | `/SetupWizard.aspx` | CVE-2024-1709 |

**Nuclei fingerprint:**
```bash
nuclei -u $T -t http/technologies/ -severity info,low,medium,high,critical
nuclei -u $T -t http/cves/ -severity high,critical -etags fuzz
```

---

## 11. Subdomain-Takeover Provider Fingerprints (27 providers)

CNAME targets + "available for claim" response signatures:

| Provider | CNAME pattern | Takeover signature |
|---|---|---|
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com` | `No such app` |
| AWS S3 | `*.s3*.amazonaws.com` | `NoSuchBucket` |
| AWS CloudFront | `*.cloudfront.net` | `Bad request` w/ specific X-Amz error |
| Azure (multiple) | `*.azurewebsites.net`, `*.blob.core.windows.net`, `*.cloudapp.net`, `*.trafficmanager.net` | Various per-product 404 patterns |
| Shopify | `shops.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| Squarespace | `*.squarespace.com` | `No Such Account` |
| Tumblr | `*.tumblr.com` | `Whatever you were looking for doesn't currently exist.` |
| WordPress | `*.wordpress.com` | `Do you want to register *.wordpress.com?` |
| Fastly | various | Fastly-specific 404 |
| Pantheon | `*.pantheonsite.io` | `The gods are wise, but do not know of the site...` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Bitbucket Pages | `*.bitbucket.io` | Repository not found |
| Tilda | `*.tilda.ws` | `Please renew your subscription` |
| Strikingly | `*.s.strikinglydns.com` | `PAGE NOT FOUND` |
| Smartling | `*.smartling.com` | Domain is not configured |
| Ngrok | `*.ngrok.io` | Tunnel not found |
| Webflow | `*.webflow.io` | Site not found |
| Zendesk | `*.zendesk.com` | `Help Center Closed` |
| Cargo | `*.cargocollective.com` | `404 Not Found` (with cargo branding) |
| Statuspage | `*.statuspage.io` | Not found |
| Intercom | `*.intercom.help` | Not found |
| Helpjuice | `*.helpjuice.com` | Not found |
| Helpscout | `*.helpscoutdocs.com` | Not found |
| Tictail | `*.tictail.com` | Not found |
| Brightcove | `*.brightcovegallery.com` | Not found |
| Smugmug | various | Not found |

For full per-provider detection signatures + edge cases, use SubdomainX or Subzy/Subjack against a freshly-fetched fingerprint database.

---

## 12. Cloud Bucket Permutation Arsenal

**6 prefixes:**
```
""           # bare candidate
backup-
assets-
static-
dev-
prod-
```

**15 suffixes:**
```
""           # bare candidate
-backup
-assets
-static
-media
-data
-uploads
-dev
-prod
-staging
-logs
-private
-public
-dump
-archive
```

**47 generic stems** (filter unless combined with target-identifying token):
```
www, mail, email, app, apps, web, webmail, ftp, cdn, static, assets, media, img, images,
videos, download, downloads, upload, uploads, data, files, docs, support, help, kb,
blog, news, dev, test, staging, stg, qa, uat, sandbox, preprod, preview, vpn,
mx, smtp, imap, pop, dns, ns, ns1, ns2, mx1, mx2
```

**Provider URL templates:**

S3:
```
https://{candidate}.s3.amazonaws.com/
https://{candidate}.s3-{region}.amazonaws.com/
https://s3.{region}.amazonaws.com/{candidate}/
```

GCS:
```
https://{candidate}.storage.googleapis.com/
https://storage.googleapis.com/{candidate}/
```

Azure Blob:
```
https://{candidate}.blob.core.windows.net/
```

**Probe technique:** HEAD first → 200/301 = exists, 403 = exists private, 404 = skip. On exists, GET root → if XML/JSON listing returns, **CRITICAL** `PUBLIC_CLOUD_BUCKET`.

---

## 13. Documentation / Wiki Leak Paths

| Platform | URL pattern |
|---|---|
| Notion | `*.notion.site/<slug>` |
| Confluence Cloud | `<target>.atlassian.net/wiki/spaces/` |
| Trello | `https://trello.com/b/<id>/<slug>` |
| Miro | `https://miro.com/app/board/<id>/` |
| GitBook | `<workspace>.gitbook.io/<book>/` |
| ReadTheDocs | `<project>.readthedocs.io` |

**Dorks:**
```
site:notion.site "{target}"
site:trello.com "{target}"
site:miro.com "{target}"
site:atlassian.net "{target}"
```

---

## 14. API Endpoints

| Service | Endpoint | Method |
|---|---|---|
| Wayback CDX | `https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original` | GET |
| Postman search | `https://www.postman.com/_api/ws/proxy` | POST (body: `{"service":"search","method":"POST","path":"/search-all","body":{"queryIndices":["collaboration.workspace"],"queryText":"{domain}","size":100}}`) |
| StackExchange | `https://api.stackexchange.com/2.3/search/advanced?site=stackoverflow.com&q={domain}&filter=withbody` | GET |
