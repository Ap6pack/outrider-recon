# Tool-Chaining Recipes

> Human-operator reference. Step-by-step multi-tool pipelines for common
> recon workflows. Covers Recon-ng, SpiderFoot, Maltego, and bash-native chains.

---

## 1. Recon-ng Module Walkthrough

**Key modules for external recon:**

| Module | Purpose |
|---|---|
| `recon/domains-hosts/hackertarget` | Subdomain enum via HackerTarget API |
| `recon/domains-hosts/certificate_transparency` | CT log subdomain discovery |
| `recon/hosts-hosts/resolve` | Resolve discovered hosts to IPs |
| `recon/domains-contacts/whois_pocs` | Registrant/admin contacts from WHOIS |
| `recon/profiles-profiles/namechk` | Username enumeration across platforms |
| `reporting/csv` | Export results to CSV |
| `reporting/json` | Export results to JSON |

**Full session -- create workspace, enumerate, resolve, export:**

```bash
recon-ng
workspaces create acme-corp
modules load recon/domains-hosts/hackertarget
options set SOURCE acme-corp.com
run
modules load recon/domains-hosts/certificate_transparency
options set SOURCE acme-corp.com
run
modules load recon/hosts-hosts/resolve
run
modules load recon/domains-contacts/whois_pocs
options set SOURCE acme-corp.com
run
modules load reporting/json
options set FILENAME /tmp/acme-corp-recon.json
run
```

API keys (set once, persist across workspaces):

```bash
keys add hackertarget_api <key>
keys add shodan_api <key>
keys add censys_api <key>
```

---

## 2. SpiderFoot Configuration

```bash
# Web UI
spiderfoot -l 127.0.0.1:5001

# CLI -- specific data types, CSV output
spiderfoot -s acme-corp.com -t EMAILADDR,INTERNET_NAME -o csv > sf-acme.csv

# CLI -- passive-only with explicit modules
spiderfoot -s acme-corp.com -t EMAILADDR,INTERNET_NAME,IP_ADDRESS \
  -m sfp_dnsresolve,sfp_crt,sfp_whois -o csv
```

**Module categories:**

| Category | Modules | Finds |
|---|---|---|
| DNS | `sfp_dnsresolve`, `sfp_dnsbrute`, `sfp_crt` | Subdomains, IPs, CNAMEs |
| Email | `sfp_emailformat`, `sfp_hunter`, `sfp_haveibeenpwned` | Addresses, breach status |
| Social | `sfp_accounts`, `sfp_names` | Usernames, profiles |
| Breach | `sfp_haveibeenpwned`, `sfp_dehashed` | Credential exposure |
| Cloud | `sfp_azuretenant`, `sfp_s3bucket`, `sfp_dnszonexfer` | Tenant info, open buckets |

**Scan profiles:** Passive-only (no target contact) / Moderate (DNS + public APIs) / Full (brute-force, active probes, port scanning).

**Export:** CSV (`-o csv`), JSON (`-o json`), GEXF via web UI (`Scans > [scan] > Export > GEXF`) for Gephi/Maltego import.

---

## 3. Maltego Transforms

**Entity types:** `Domain` (seed), `DNSName`, `EmailAddress`, `Person`, `Company`, `IPv4Address`.

**Key transforms:**

```text
Domain  --> [To DNS Name]       --> subdomains, NS, MX records
Domain  --> [To MX Record]      --> mail infrastructure
Domain  --> [To Website]        --> web technologies, CMS detection
Email   --> [To Person]         --> OSINT on registrant/admin contacts
IP      --> [To Netblock]       --> CIDR ownership, ASN mapping
DNSName --> [To IP Address]     --> resolve all discovered hosts
```

**Workflow:** Start with `Domain` entity. Run `To DNS Name` + `To MX Record`. Select `DNSName` results, run `To IP Address`. Select IPs, run `To Netblock` for ASN context. Export: `Export > CSV Table` or `Export > GraphML`.

**Hub vs local:** Hub transforms run server-side (Shodan, VirusTotal, HIBP -- require API keys in Transform Hub). Local transforms run on your machine (DNS, WHOIS).

**Import from other tools:**

```text
SpiderFoot GEXF:  File > Import Graph > GEXF
Recon-ng CSV:     File > Import > CSV Table (map columns to entity types)
```

---

## 4. Bash-Native Pipelines

**Subdomain discovery pipeline:**

```bash
subfinder -d acme-corp.com -silent | \
  httpx -silent -status-code -title -tech-detect -o alive.txt | \
  awk '{print $1}' | \
  nuclei -t cves/ -t exposures/ -t misconfiguration/ -jsonl -o findings.jsonl
jq -r '[.host, .template_id, .severity] | @tsv' findings.jsonl | sort -t$'\t' -k3
```

**Secret hunting pipeline:**

```bash
trufflehog git https://github.com/acme-corp/webapp.git --json 2>/dev/null | \
  jq -c '{detector: .DetectorName, file: .SourceMetadata.Data.Git.file, \
          commit: .SourceMetadata.Data.Git.commit[:8], verified: .Verified}' | \
  tee findings.jsonl
jq -r '.detector' findings.jsonl | sort | uniq -c | sort -rn
```

**DNS recon pipeline:**

```bash
DOMAIN="acme-corp.com"
for TYPE in A AAAA MX NS TXT CNAME SOA; do
  dig +noall +answer "$DOMAIN" "$TYPE" 2>/dev/null
done | awk '{print $1, $4, $5}' | sort -u > dns-records.txt

# Bulk parallel resolution
cat subs.txt | xargs -I {} -P 30 sh -c \
  'IP=$(dig +short A {} | head -1); [ -n "$IP" ] && echo "{} $IP"' | sort > resolved.txt
```

**Screenshot pipeline:**

```bash
cat alive.txt | awk '{print $1}' | \
  gowitness scan file -f - --screenshot-path ./screenshots --timeout 15
gowitness report generate -n report.html
```

**Full engagement pipeline (5+ tools, JSONL output):**

```bash
#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?Usage: engage.sh <domain>}"
OUT="./recon-${TARGET}-$(date +%Y%m%d)"; mkdir -p "$OUT"

# Phase 1 -- passive subdomain discovery
subfinder -d "$TARGET" -silent > "$OUT/subs-sf.txt"
amass enum -passive -d "$TARGET" -o "$OUT/subs-am.txt" 2>/dev/null
cat "$OUT"/subs-*.txt | sort -u > "$OUT/subs-all.txt"

# Phase 2 -- alive check + tech fingerprint
httpx -l "$OUT/subs-all.txt" -silent -status-code -title -tech-detect \
  -json -o "$OUT/alive.jsonl"

# Phase 3 -- port scan alive hosts
jq -r '.url' "$OUT/alive.jsonl" | sed 's|https\?://||;s|/.*||' | sort -u > "$OUT/hosts.txt"
nmap -iL "$OUT/hosts.txt" -T3 -sV --top-ports 1000 -oA "$OUT/nmap" 2>/dev/null

# Phase 4 -- vulnerability scan
jq -r '.url' "$OUT/alive.jsonl" | \
  nuclei -t cves/ -t exposures/ -jsonl -o "$OUT/vulns.jsonl"

# Phase 5 -- screenshots
jq -r '.url' "$OUT/alive.jsonl" | \
  gowitness scan file -f - --screenshot-path "$OUT/screenshots" --timeout 15

echo "Subs: $(wc -l < "$OUT/subs-all.txt") | Alive: $(wc -l < "$OUT/alive.jsonl") | Vulns: $(wc -l < "$OUT/vulns.jsonl")"
```

---

## 5. SpiderFoot to Maltego Bridge

```bash
# Export GEXF via web UI: Scans > [scan] > Export > GEXF
# Or via API:
curl -s "http://127.0.0.1:5001/scanexportgexf?id=<scan_id>" -o sf-graph.gexf
```

Import into Maltego: `File > Import Graph > GEXF`. Map entity types (`Domain -> maltego.Domain`, `IP -> maltego.IPv4Address`, `Email -> maltego.EmailAddress`). Run Hub transforms to enrich (Shodan, VirusTotal, PassiveTotal). Export enriched graph: `Export > CSV Table` for report integration.

---

## 6. Recon-ng to Pipeline Bridge

**Export:**

```bash
# Inside recon-ng
modules load reporting/json
options set FILENAME /tmp/recon-export.json
run
```

**Normalize into outrider-recon finding schema:**

```bash
jq -r '.hosts[] | {
  asset: .host, ip: .ip_address, source: "recon-ng",
  type: "subdomain", discovered: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
}' /tmp/recon-export.json > normalized.jsonl

jq -r '.contacts[] | {
  asset: .email, name: (.first_name + " " + .last_name), source: "recon-ng",
  type: "contact", discovered: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
}' /tmp/recon-export.json >> normalized.jsonl
```

**Feed into downstream tools:**

```bash
# Into nuclei
jq -r 'select(.type=="subdomain") | .asset' normalized.jsonl | \
  httpx -silent | nuclei -t cves/ -jsonl -o vuln-findings.jsonl

# Into custom scan script
jq -r 'select(.type=="subdomain") | .asset' normalized.jsonl | \
  while read -r host; do ./custom-probe.sh "$host" >> probe-results.jsonl; done
```

---
