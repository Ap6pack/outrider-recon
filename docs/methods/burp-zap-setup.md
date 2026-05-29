# Burp Suite and ZAP Engagement Setup

> Human-operator reference. Proxy configuration recipes for authorized
> external recon and bug bounty engagements. Covers Burp Suite Professional
> and OWASP ZAP.

---

## 1. Burp Suite -- Engagement Config

New project per engagement: `File > New Project on Disk` -- name it `<program>-<YYYY-MM-DD>.burp`.

**Scope:** `Target > Scope > Use advanced scope control`

```text
Include:  Host or IP range: *.target.example   Port: Any   File: ^/.*
Include:  Host or IP range: 203.0.113.0/24     (add CIDR blocks directly)

Exclude:  *.google.com  *.googleapis.com  *.gstatic.com  *.doubleclick.net
          *.google-analytics.com  *.facebook.com  *.sentry.io  *.nr-data.net
```

**Session handling** -- keep auth alive during long scans:

```text
Project Options > Sessions > Session Handling Rules > Add
  Rule actions: Check session is valid > If invalid, run macro (login sequence)
  Scope: Use suite scope     Tools: Scanner, Intruder, Repeater
```

**Project options:** Timeouts 30s normal / 15s open. Follow redirects max 5. Scanner resource pool 8 threads. Max response size 10 MB. Enable all-traffic disk logging.

---

## 2. Burp Suite -- Useful Extensions

Install via `Extender > BApp Store` unless noted.

| Extension | Source | Purpose |
|---|---|---|
| **Autorize** | BApp Store | Detect broken access control -- replay with low-priv session |
| **Logger++** | BApp Store | Full traffic logging with regex filters, export to CSV/ES |
| **Param Miner** | BApp Store | Discover hidden params, headers, web cache poisoning vectors |
| **GAP** | [GitHub](https://github.com/xnl-h4ck3r/GAP-Burp-Extension) | Extract params/paths/links from JS/HTML responses |
| **JS Link Finder** | BApp Store | Extract endpoints and paths from JavaScript files |
| **Turbo Intruder** | BApp Store | Python-scriptable HTTP fuzzer, 10-100x faster than Intruder |
| **Hackvertor** | BApp Store | Tag-based encoding/decoding for WAF bypass payloads |
| **ActiveScan++** | BApp Store | Host header injection, cache poisoning, additional active checks |
| **Retire.js** | BApp Store | Identify vulnerable front-end JavaScript libraries |
| **HTTP Request Smuggler** | BApp Store | Detect CL.TE / TE.CL request smuggling variants |

---

## 3. Burp Suite -- Recon-Specific Workflows

**Passive crawl then sitemap export:** Browse target with proxy set to `127.0.0.1:8080`. Then `Target > Site map > right-click root > Engagement tools > Discover content`. Select all, copy URLs, dedupe:

```bash
pbpaste | sort -u > endpoints.txt
```

**Regex search for leaked secrets** in `Proxy > HTTP History > Search > Regex`:

```text
(?i)(api[_-]?key|secret|token|password|aws_access)["\s:=]+["']?[A-Za-z0-9/+=]{16,}
```

**Directory brute-force:** Intruder with `SecLists/Discovery/Web-Content/raft-medium-directories.txt`, 10 threads, 100ms throttle. Grep match on 200, 301, 302, 403.

**Bambda filter for interesting responses:**

```java
return requestResponse.response().bodyToString().contains("\"token\"")
    || requestResponse.response().body().length() > 50000;
```

**Export to JSONL for pipeline:**

```bash
python3 -c "
import xml.etree.ElementTree as ET, json, sys
tree = ET.parse(sys.argv[1])
for item in tree.findall('.//item'):
    print(json.dumps({'url': item.findtext('url',''),
        'status': item.findtext('status',''),
        'mime': item.findtext('mimetype','')}))
" burp-export.xml > endpoints.jsonl
```

---

## 4. OWASP ZAP -- Engagement Config

New session: `File > New Session` -- save as `<program>-<YYYY-MM-DD>.session`.

**Context:** `Sites > right-click target > Include in Context > New Context`

```text
Include: https://target.example.*    https://api.target.example.*
Exclude: https://.*\.google\.com.*   https://.*\.googleapis\.com.*
```

**Custom scan policy:** `Analyse > Scan Policy Manager > Add` -- name `recon-light`. Disable all categories, enable only Information Gathering and Server Security (low threshold, low strength).

**Authentication:** `Context > Authentication > Form-based`. Set login URL, POST data with `{%username%}` / `{%password%}` tokens, logged-in indicator regex `logout|dashboard`.

**Headless API mode:**

```bash
/opt/zaproxy/zap.sh -daemon -host 0.0.0.0 -port 8090 \
  -config api.disablekey=true -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
curl -s http://localhost:8090/JSON/core/view/version/
```

---

## 5. OWASP ZAP -- Automation Framework

```yaml
---
env:
  contexts:
    - name: "target-recon"
      urls: ["https://target.example"]
      includePaths: ["https://target.example.*"]
      excludePaths: [".*\\.google\\.com.*"]
  parameters:
    failOnError: true
    progressToStdout: true
jobs:
  - type: spider
    parameters:
      context: "target-recon"
      maxDuration: 10
      maxDepth: 5
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
  - type: activeScan
    parameters:
      context: "target-recon"
      maxRuleDurationInMins: 2
      maxScanDurationInMins: 30
      policy: "recon-light"
  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "/tmp/zap-reports"
      reportFile: "zap-recon-report"
```

```bash
# Run the automation plan
/opt/zaproxy/zap.sh -cmd -autorun recon-plan.yaml

# Docker one-liner for CI/CD scheduled scans
docker run --rm -v "$(pwd):/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://target.example -J report.json -r report.html
```

**Transform ZAP JSON to finding schema:**

```bash
jq '[.site[].alerts[] | select(.riskcode | tonumber >= 2) | {
  url: .instances[0].uri, risk: .riskdesc, name: .name,
  cwe: .cweid, evidence: .instances[0].evidence
}]' /tmp/zap-reports/zap-recon-report.json > findings.jsonl
```

---

## 6. Traffic Tagging

Tag all outbound requests so targets can identify your traffic as authorized.

**Burp -- Match and Replace:** `Proxy > Options > Match and Replace > Add`

```text
Type: Request header    Match: (empty)    Replace: X-Bug-Bounty: HackerOne-<handle>
Type: Request header    Match: (empty)    Replace: X-Bug-Bounty-Program: <program-slug>
```

**ZAP -- Replacer add-on:** Install "Replacer" from Marketplace. `Options > Replacer > Add`:

```text
Match Type: Request Header (will add if not present)
Match String: X-Bug-Bounty      Replacement: HackerOne-<handle>
Initiators: All                 Enable: checked
```

**Why:** Programs require it. Target SOC can filter your traffic from real attacks. Demonstrates good faith if your scanner trips an IDS. Some programs grant safe harbor only to tagged traffic.

---

## 7. Proxy Chaining for OPSEC

**Burp upstream SOCKS5:** `Settings > Network > Connections > SOCKS proxy`

```text
Host: 127.0.0.1    Port: 9050    DNS over SOCKS: checked (critical for anonymity)
```

**ZAP upstream proxy:** `Options > Connection > Use an outgoing proxy server`

```text
Address: 127.0.0.1    Port: 9050    SOCKS version: 5
```

**SSH SOCKS tunnel:**

```bash
ssh -D 9050 -f -C -q -N user@vps.example.com
curl --socks5-hostname 127.0.0.1:9050 https://ifconfig.me
```

**Per-engagement proxy rotation** -- never share exit IPs across targets:

```bash
# proxychains4 for full rotation
# /etc/proxychains4.conf: dynamic_chain, proxy_dns, socks5 127.0.0.1 9050-9052
proxychains4 java -jar burpsuite_pro.jar
```

Maintain a proxy map per engagement:

```text
# ~/.config/outrider/proxy-map.txt
target-a.example    vps-us-east    9050
target-b.example    vps-eu-west    9051
target-c.example    vps-ap-south   9052
```

---
