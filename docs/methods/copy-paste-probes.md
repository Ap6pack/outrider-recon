# Copy-Paste Probes & API Recipes

> Human-operator reference. Curl one-liners, httpx bulk probes, and API query recipes
> for manual OSINT workflows. Extracted from skill files for clean separation.

---

## Web Surface Probes (curl one-liners)

```bash
T="https://target.example"

# .git/config (CRITICAL)
curl -sk -m 10 "$T/.git/config" | grep -E '\[core\]|\[remote|repositoryformatversion'

# .env (CRITICAL)
curl -sk -m 10 "$T/.env" | grep -E '^[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*='

# Spring Boot actuator/env (CRITICAL)
curl -sk -m 10 "$T/actuator/env" | grep -E '"propertySources"|systemProperties|systemEnvironment'

# Spring Boot heapdump (CRITICAL)
curl -sk -m 30 "$T/actuator/heapdump" -o /tmp/heap && file /tmp/heap | grep -i 'HPROF\|data'

# Elasticsearch (HIGH)
curl -sk -m 10 "$T/_cat/indices?v"

# Jenkins console (HIGH)
curl -sk -m 10 "$T/script" | grep -iE 'Jenkins|Script Console'

# Tomcat manager — 401 = present+auth-gated; 200 = no auth
curl -sk -m 10 "$T/manager/html" -w '%{http_code}\n' | tail -1

# security.txt (INFO)
curl -sk -m 10 "$T/.well-known/security.txt"
```

---

## GraphQL Introspection Probe

```bash
curl -sk -m 15 -X POST "https://target.example/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { __schema { types { name kind } queryType { name } mutationType { name } } }"}' | jq '.data.__schema.types | length'
```

---

## SSO Subdomain Prefixes

```bash
D="target.example"
for prefix in auth login sso idp iam identity accounts oauth; do
  echo "=== ${prefix}.${D} ===" && \
  curl -sk -m 10 "https://${prefix}.${D}/.well-known/openid-configuration" -o /dev/null -w '%{http_code}\n'
done
```

---

## Cloud Bucket Probes

```bash
B="candidate-bucket-name"
curl -sk -m 10 -I "https://${B}.s3.amazonaws.com/" -w 'STATUS:%{http_code}\n' | head -20
curl -sk -m 10 "https://${B}.s3.amazonaws.com/?list-type=2" | head -50
curl -sk -m 10 -I "https://${B}.storage.googleapis.com/"
curl -sk -m 10 -I "https://${B}.blob.core.windows.net/"
```

---

## Bulk Probe with httpx

```bash
cat subdomains.txt | httpx -sc -title -tech-detect -path /actuator/env,/.git/config,/.env -mc 200,301,403
```

---

## Wayback CDX Recipes

```bash
D="target.example"
# All URLs
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=timestamp,original&limit=10000"

# JS bundles only (with secret scan)
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.js&output=json&fl=timestamp,original&filter=statuscode:200" | \
  jq -r '.[1:][] | "\(.[0]) \(.[1])"'

# Legacy app pivot (when *.js empty for brochure-ware sites)
for ext in asp aspx php jsp cfm; do
  curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.${ext}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=500"
done
```

---

## Postman Public Workspace Search

```bash
curl -sk -m 15 \
  "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -H 'X-Entity-Team-Id: 0' \
  -d '{"service":"search","method":"POST","path":"/search-all","body":{"queryIndices":["collaboration.workspace","runtime.collection","runtime.request"],"queryText":"acme.com","size":100,"from":0,"clientTraceId":"","queryAllIndices":false,"domain":"public"}}' | jq '.data[]'
```

Pagination via `from` (0, 100, 200...). Run secret catalog over every env var, pre-request script, and request body extracted.

---

## Stack Exchange OSINT Sweep

```bash
curl -sk "https://api.stackexchange.com/2.3/search/advanced?site=stackoverflow.com&q=target.example&filter=withbody&pagesize=100"
```

Extract code blocks with `<pre><code>([\s\S]*?)</code></pre>`, run secret catalog. Also check: `serverfault.com`, `dba.stackexchange.com`, `devops.stackexchange.com`, `security.stackexchange.com`, `superuser.com`, `unix.stackexchange.com`, `networkengineering.stackexchange.com`.

---

## Public SaaS Collaboration Dorks

```
site:trello.com "{target}"
site:notion.so "{target}"
site:miro.com "{target}"
site:*.atlassian.net "{target}"
site:airtable.com "{target}"
```

---

## Vulnerability Prioritization Workflow

```bash
# 1. Get EPSS score for a CVE
curl -sk "https://api.first.org/data/v1/epss?cve=CVE-2024-3400" | jq '.data[0]'

# 2. Check if in CISA KEV
curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-3400")'

# 3. Check ExploitDB
searchsploit cve 2024-3400

# 4. Check Metasploit
msfconsole -q -x "search cve:2024-3400; exit"
```

**Bulk prioritization** (given a Nuclei scan output with N CVEs):

```bash
# Extract CVEs from nuclei JSON output
jq -r '.info.classification.["cve-id"][]?' nuclei-results.json | sort -u > cves.txt

# Annotate each with EPSS + KEV
while IFS= read -r CVE; do
  EPSS=$(curl -sk "https://api.first.org/data/v1/epss?cve=$CVE" | jq -r '.data[0].epss // "N/A"')
  KEV=$(curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
    jq --arg c "$CVE" '.vulnerabilities[] | select(.cveID == $c) | .vulnerabilityName // empty')
  KEV_FLAG=$([ -n "$KEV" ] && echo "KEV" || echo "")
  echo "$CVE | EPSS:$EPSS | $KEV_FLAG"
done < cves.txt | sort -t: -k2 -nr
```

---

