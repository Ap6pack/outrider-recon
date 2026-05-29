---
name: secrets-and-dorks
description: "48-pattern secret regex catalog, 70 dork corpus across 9 categories, GitHub code-search dorks, and 9 read-only credential validators for authorized secret discovery and verification."
version: 1.0.0
triggers:
  - secret scanning
  - secret leak
  - leaked credential
  - github dorking
  - google dorking
  - bing dorking
  - DDG dorking
  - regex catalog
  - API key regex
  - Anthropic API key
  - OpenAI API key
  - AWS key
  - GitHub PAT
  - secret validator
  - breach lookup
  - credential validation
  - JS secret scan
  - sourcemap leak
---

# Secrets & Dorks

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only. Read-only validators only — never use a validated credential to create, modify, or delete anything.

---

## BEHAVIORAL CONTRACT

**When triggered:** Secret scanning, leaked credential hunting, GitHub/Google/Bing dorking, API key discovery, or credential verification is needed.

**Execute:**
1. Run the 48-pattern secret catalog (§1) against the target corpus — GitHub code, Postman workspaces, JS bodies, sourceMaps, mobile strings, Wayback HTML, paste sites, Stack Exchange code blocks. Process patterns in order (most-specific first) to minimize false positives.
2. Run the dork corpus (§2) across Google, Bing, Brave, DDG — substitute `{domain}` and `{company}`. Run across multiple engines (they surface different results).
3. Run GitHub code-search dorks (§3) against the target domain stem, full domain, and company name.
4. For every secret match: classify by catalog severity, then validate using the matching read-only validator from §4 (if one exists for that provider).
5. Never validate credentials for which no read-only endpoint exists. Never validate AWS root ARNs (`:root`).
6. For validated-live credentials: emit `SECRET_LEAK` finding at catalog severity, then chain to `post-discovery` for enumeration (gated on RoE).

**Output:** `SECRET_LEAK` findings per `osint-methodology` §3 schema. Validator results per §4.10 schema (status, provider, account_id, scope, checked_at, detectability).

**Severity rules:** Per catalog table (§1). False-positive-prone patterns (22 JWT, 23 Bearer, 29 Generic) require context check before emitting.

**Gating rules:** Read-only validators only. Never create/modify/delete/send. Tag every validation with detectability + checked_at UTC.

**Chain to:** Feed validated-live credentials to `post-discovery` for enumeration workflows. Feed GitHub dork results through §1 catalog for automated secret scanning. Feed all findings to `analysis-and-reporting` for severity classification and attack-path hints.

---

## 1. Secret-Pattern Catalog — 48 Patterns

Run against: GitHub code, Postman workspaces, JS bodies, sourcesContent blobs, mobile strings, Wayback HTML, paste sites, Stack Exchange code blocks. **Order matters: most-specific first.**

| # | Name | Regex | Severity | Category |
|---|---|---|---|---|
| 1 | AWS Access Key | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | **CRITICAL** | aws |
| 2 | AWS Secret Key (typed) | `(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"\s:=]+([A-Za-z0-9/+=]{40})` | **CRITICAL** | aws |
| 3 | AWS Secret (loose) | `(?i)aws(.{0,20})?(secret\|sk)["'=: ]+([0-9a-z/+=]{40})` | HIGH | aws |
| 4 | GCP Service Account JSON | `"type"\s*:\s*"service_account"` | **CRITICAL** | gcp |
| 5 | Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | HIGH | gcp |
| 6 | GitHub Classic PAT | `\bghp_[A-Za-z0-9]{36}\b` | **CRITICAL** | github |
| 7 | GitHub Fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | **CRITICAL** | github |
| 8 | GitHub OAuth | `\bgho_[A-Za-z0-9]{36}\b` | HIGH | github |
| 9 | GitHub Server-to-Server | `\bgh[usr]_[A-Za-z0-9]{36,}\b` | HIGH | github |
| 10 | Stripe Live Key | `\bsk_live_[0-9A-Za-z]{24,}\b` | **CRITICAL** | stripe |
| 11 | Stripe Test Key | `\bsk_test_[0-9A-Za-z]{24,}\b` | LOW | stripe |
| 12 | Slack Token | `\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b` | HIGH | slack |
| 13 | Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | MEDIUM | slack |
| 14 | SendGrid Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | HIGH | email_svc |
| 15 | Mailgun Key (v1) | `\bkey-[0-9a-zA-Z]{32}\b` | HIGH | email_svc |
| 16 | Mailgun Key (loose) | `\bkey-[0-9a-f]{32}\b` | HIGH | email_svc |
| 17 | Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` | HIGH | twilio |
| 18 | Twilio Account SID | `\bAC[a-f0-9]{32}\b` | MEDIUM | twilio |
| 19 | Twilio Auth Token | `(?i)twilio(.{0,20})?(auth\|token)["'=: ]+([a-f0-9]{32})` | HIGH | twilio |
| 20 | Heroku API Key | `(?i)heroku(.{0,20})?api["'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` | MEDIUM | paas |
| 21 | Firebase URL | `\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b` | LOW | firebase |
| 22 | JWT (any) | `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b` | MEDIUM | jwt |
| 23 | Bearer Token Assignment | `(?i)authorization["'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}` | MEDIUM | bearer |
| 24 | Basic Auth in URL | `https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+` | MEDIUM | basic_auth |
| 25 | RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | **CRITICAL** | private_key |
| 26 | EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | **CRITICAL** | private_key |
| 27 | OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | **CRITICAL** | private_key |
| 28 | Generic Private Key | `-----BEGIN (DSA \|PGP \|)PRIVATE KEY-----` | **CRITICAL** | private_key |
| 29 | Generic API Key | `(?i)(?:api[_\-]?key\|apikey\|api_secret\|access_token\|secret[_\-]?token)['"\s:=]+["']([A-Za-z0-9+/=_\-]{24,})["']` | MEDIUM | generic |
| 30 | Anthropic API Key | `\bsk-ant-(?:api03\|admin01)-[A-Za-z0-9_\-]{93,}\b` | **CRITICAL** | ai_api |
| 31 | OpenAI API Key (legacy) | `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b` | **CRITICAL** | ai_api |
| 32 | OpenAI Project Key | `\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b` | **CRITICAL** | ai_api |
| 33 | OpenAI User Session | `\bsess-[A-Za-z0-9]{40}\b` | HIGH | ai_api |
| 34 | HuggingFace Token | `\bhf_[A-Za-z0-9]{30,}\b` | HIGH | ai_api |
| 35 | Cloudflare API Token | `\b[A-Za-z0-9_\-]{40}\b` (needs `(?i)cloudflare` context) | HIGH | infra_api |
| 36 | Cloudflare Global API Key | `(?i)cf[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{37})` | **CRITICAL** | infra_api |
| 37 | DigitalOcean Token | `\bdop_v1_[a-f0-9]{64}\b` | HIGH | infra_api |
| 38 | npm Token (Modern) | `\bnpm_[A-Za-z0-9]{36}\b` | HIGH | package_registry |
| 39 | PyPI Token | `\bpypi-AgENdGV[A-Za-z0-9_\-]+\b` | HIGH | package_registry |
| 40 | Docker Hub PAT | `\bdckr_pat_[A-Za-z0-9_\-]{27,}\b` | HIGH | package_registry |
| 41 | Atlassian API Token | `\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b` | HIGH | saas_api |
| 42 | New Relic License Key | `\b(?:NRAA\|NRAK\|NRBR)-[A-F0-9]{27}\b` | MEDIUM | observability |
| 43 | DataDog API Key | `(?i)dd[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{32})` | HIGH | observability |
| 44 | Sentry DSN | `https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+` | LOW | observability |
| 45 | ngrok Auth Token | `\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b` (needs `(?i)ngrok` context) | MEDIUM | tunneling |
| 46 | Linear API Key | `\blin_api_[A-Za-z0-9]{40}\b` | MEDIUM | saas_api |
| 47 | Discord Bot Token | `\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b` | HIGH | bot_token |
| 48 | Telegram Bot Token | `\b\d{8,10}:[A-Za-z0-9_\-]{35}\b` | HIGH | bot_token |

**False-positive notes:**
- Patterns 22 (JWT), 23 (Bearer), 29 (Generic) trigger on test/example data. Always check *context*.
- Pattern 16 (Mailgun loose) and 11 (Stripe test) are intentionally noisy; severity is low.
- Pattern 24 (Basic auth URL) catches monitoring URLs and CI debug URLs — verify before alerting.

---

## 2. Dork Corpus — 70 Templates, 9 Categories

Substitute `{domain}` = `example.com`, `{company}` = `Acme Corporation`. Run via Google, Bing, Brave, DDG, Yandex — engines surface different results.

### 2.1 Files
```
site:{domain} filetype:env
site:{domain} ext:env OR ext:ini OR ext:cfg OR ext:conf
site:{domain} ext:sql OR ext:sqlite OR ext:dump OR ext:bak
site:{domain} ext:pem OR ext:key OR ext:p12 OR ext:pfx
site:{domain} ext:log
site:{domain} intitle:"index of"
site:{domain} inurl:.git OR inurl:/.git/
site:{domain} inurl:backup OR inurl:.bak OR inurl:old
site:{domain} ext:yml OR ext:yaml
site:{domain} ext:properties
```

### 2.2 Admin / Login Panels
```
site:{domain} inurl:admin OR inurl:login OR inurl:sso OR inurl:dashboard
site:{domain} intitle:"phpMyAdmin"
site:{domain} intitle:"Jenkins"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Splunk"
site:{domain} (intitle:"login" OR intitle:"sign in")
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Swagger" OR intitle:"OpenAPI"
site:{domain} inurl:phpinfo
```

### 2.3 Secrets / Credential Leakage
```
"{domain}" ("api_key" OR "apikey" OR "access_token")
"{domain}" (password OR passwd OR pwd)
site:pastebin.com "{domain}"
site:ghostbin.com "{domain}"
site:rentry.co "{domain}"
site:gist.github.com "{domain}"
site:hastebin.com "{domain}"
"{domain}" "BEGIN RSA PRIVATE KEY"
```

### 2.4 Cloud / CI / Shadow-IT
```
site:s3.amazonaws.com "{domain}"
site:storage.googleapis.com "{domain}"
site:blob.core.windows.net "{domain}"
site:digitaloceanspaces.com "{domain}"
site:trello.com "{domain}"
site:*.atlassian.net "{domain}"
site:dev.azure.com "{domain}"
site:bitbucket.org "{domain}"
site:firebaseio.com "{domain}"
site:herokuapp.com "{domain}"
```

### 2.5 Docs / Intel Mining
```
site:{domain} filetype:pdf (confidential OR internal OR restricted)
site:{domain} filetype:xlsx OR filetype:csv
site:{domain} filetype:docx
site:scribd.com "{company}"
"{company}" filetype:pdf (salary OR payroll OR org-chart OR "organization chart")
site:slideshare.net "{company}"
```

### 2.6 Vuln Indicators
```
site:{domain} intext:"sql syntax" OR intext:"you have an error in your sql"
site:{domain} intext:"Warning: mysql_"
site:{domain} intext:"Fatal error:" intext:"on line"
site:{domain} intext:"stack trace" OR intext:"Traceback (most recent call last)"
"Apache/2.4.49" site:{domain}
site:{domain} inurl:wp-content OR inurl:wp-includes
site:{domain} intext:"Directory listing for /"
site:{domain} intitle:"Apache2 Ubuntu Default Page"
```

### 2.7 Internal Tool Exposure
```
site:{domain} intitle:"Prometheus Time Series"
site:{domain} intitle:"Argo CD"
site:{domain} intitle:"Sonarqube"
site:{domain} intitle:"Confluence"
site:{domain} intitle:"Jira"
site:{domain} inurl:"/jenkins/"
site:{domain} intitle:"Portainer"
site:{domain} intitle:"Rancher"
```

### 2.8 Backup / Dump File Extensions
```
site:{domain} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp
site:{domain} ext:tar OR ext:tar.gz OR ext:tgz OR ext:zip OR ext:rar OR ext:7z
site:{domain} ext:db OR ext:sqlite OR ext:sqlite3 OR ext:mdb
site:{domain} ext:dump OR ext:rdb OR ext:bson
site:{domain} (intext:"-- MySQL dump" OR intext:"PostgreSQL database dump")
```

### 2.9 Sector-Specific
```
# Healthcare
site:{domain} (filetype:pdf OR filetype:xlsx) (HIPAA OR PHI OR "patient records")
site:{domain} ("DICOM" OR "HL7" OR "ICD-10")

# Finance
site:{domain} (filetype:pdf OR filetype:xlsx) (SOC OR "audit report" OR "internal control")
site:{domain} ("SWIFT" OR "BIC" OR IBAN OR "wire transfer")

# Gov / public sector
site:{domain} (filetype:pdf OR filetype:doc) (FOUO OR "controlled unclassified" OR CUI)
```

---

## 3. GitHub Code-Search Dorks — 13 Dorks

Apply each to `{target}` (root domain stem), `{domain}` (full root domain), and `{company}`:

```
"{target}" filename:.env
"{target}" filename:.env.example
"{target}" filename:config
"{target}" AWS_ACCESS_KEY_ID
"{target}" AWS_SECRET_ACCESS_KEY
"{target}" password
"{target}" api_key
"{target}" secret
"{target}" authorization: Bearer
"{target}" filename:id_rsa
"{target}" filename:.git-credentials
"{target}" filename:wp-config.php
"@{domain}" password
```

For each result: fetch file → run secret catalog → if hit → `SECRET_LEAK` finding with catalog severity, evidence = repo URL + file path + matched secret (truncate, last 4 chars only).

---

## 4. Read-Only Secret Validators

**Hard rules:** read-only endpoint only. Never create, modify, delete, or send anything. Tag every validation with detectability and UTC `checked_at`.

### 4.1 Postman PMAK
```bash
curl -sk -m 10 -H "X-Api-Key: PMAK-..." https://api.getpostman.com/me | jq .
```
`200` → live (returns user id/email). `401` → dead. Detectability: low.

### 4.2 AWS Access Key
```python
import boto3
sts = boto3.client('sts', aws_access_key_id='AKIA...', aws_secret_access_key='...', region_name='us-east-1')
print(sts.get_caller_identity())
```
Valid → returns Account ID + ARN + UserId. `:root` ARN = do NOT validate. Detectability: **medium** (CloudTrail logs GetCallerIdentity).

### 4.3 GitHub PAT
```bash
curl -sk -m 10 -H "Authorization: token ghp_..." https://api.github.com/user -D /tmp/h | jq -r '.login,.email'
grep -i 'X-OAuth-Scopes' /tmp/h
```
`200` → live. Scope in `X-OAuth-Scopes`. `repo` scope = write access. Detectability: low.

### 4.4 Slack Token
```bash
curl -sk -m 10 -H "Authorization: Bearer xoxb-..." -X POST https://slack.com/api/auth.test | jq .
```
`{"ok": true}` → live (includes team, user IDs). Detectability: low.

### 4.5 Anthropic API Key
```bash
curl -sk -m 10 -H "x-api-key: sk-ant-api03-..." -H "anthropic-version: 2023-06-01" \
  https://api.anthropic.com/v1/models | jq '.data | length'
```
`200` → live. `401` → dead. `403 org_disabled` → key valid but org disabled. Detectability: low.

### 4.6 OpenAI API Key
```bash
curl -sk -m 10 -H "Authorization: Bearer sk-..." https://api.openai.com/v1/models | jq '.data | length'
```
`200` → live. `429` → live but quota exhausted. Detectability: low.

### 4.7 npm Token
```bash
curl -sk -m 10 -H "Authorization: Bearer npm_..." https://registry.npmjs.org/-/whoami | jq .
```
`200` with `{"username": "..."}` → live. Detectability: low.

### 4.8 Atlassian API Token
```bash
curl -sk -m 10 -u "email:ATATT3xFfGF0_..." \
  https://<workspace>.atlassian.net/rest/api/3/myself | jq .
```
`200` → live (returns account profile). Detectability: low.

### 4.9 DataDog API + APP Key
```bash
curl -sk -m 10 -H "DD-API-KEY: ..." -H "DD-APPLICATION-KEY: ..." \
  https://api.datadoghq.com/api/v1/validate | jq .
```
`200` → both keys valid. `403` → either key invalid. Detectability: low; appears in DataDog audit log.

### 4.10 Validator Output Schema
```json
{
  "status": "verified_live | verified_dead | scope_restricted | validation_skipped_by_policy",
  "provider": "postman | aws | github | slack | anthropic | openai | npm | atlassian | datadog",
  "account_id": "<opaque>",
  "scope": "<freeform>",
  "checked_at": "<UTC ISO8601>",
  "detectability": "low | medium | high"
}
```

After validator confirms live → see `post-discovery` sub-skill for enumeration workflows (NOT read-only).
