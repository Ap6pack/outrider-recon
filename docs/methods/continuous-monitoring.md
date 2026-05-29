# Continuous Monitoring Playbook

> Human-operator reference. Daily/weekly diff scripts, alert pipelines,
> false-positive tuning, and long-running ASM engagement patterns.

---

## 1. Daily Diff Pipeline

### Subdomain Diff

```bash
D="target.example"; DIR="$HOME/recon/$D/subs"; mkdir -p "$DIR"
TODAY=$(date -u +%Y%m%d); YESTERDAY=$(date -u -d "yesterday" +%Y%m%d)
subfinder -d "$D" -silent -all | sort -u > "$DIR/${TODAY}.txt"
if [ -f "$DIR/${YESTERDAY}.txt" ]; then
  comm -13 "$DIR/${YESTERDAY}.txt" "$DIR/${TODAY}.txt" > "$DIR/${TODAY}_new.txt"
  COUNT=$(wc -l < "$DIR/${TODAY}_new.txt")
  [ "$COUNT" -gt 0 ] && echo "[+] $COUNT new subdomains" && cat "$DIR/${TODAY}_new.txt"
fi
```

### CT Log Monitoring

Poll crt.sh daily (certstream is real-time but noisy; crt.sh fits cron better).

```bash
D="target.example"; DIR="$HOME/recon/$D/certs"; mkdir -p "$DIR"; TODAY=$(date -u +%Y%m%d)
curl -sk "https://crt.sh/?q=%25.${D}&output=json" | \
  jq -r '.[].name_value' | sort -u > "$DIR/${TODAY}.txt"
[ -f "$DIR/last.txt" ] && comm -13 "$DIR/last.txt" "$DIR/${TODAY}.txt" | tee "$DIR/${TODAY}_new.txt"
cp "$DIR/${TODAY}.txt" "$DIR/last.txt"
```

### DNS Record Diff

```bash
D="target.example"; DIR="$HOME/recon/$D/dns"; mkdir -p "$DIR"
TODAY=$(date -u +%Y%m%d); YESTERDAY=$(date -u -d "yesterday" +%Y%m%d)
for RR in A MX TXT NS AAAA CNAME; do
  dig +short "$D" "$RR" | sort > "$DIR/${TODAY}_${RR}.txt"
  [ -f "$DIR/${YESTERDAY}_${RR}.txt" ] && \
    diff -q "$DIR/${YESTERDAY}_${RR}.txt" "$DIR/${TODAY}_${RR}.txt" >/dev/null || echo "[!] $RR changed"
done
```

---

## 2. Weekly Deep Scan

### Full Nuclei Sweep

Weekly, not daily -- too noisy and burns rate limits on cloud targets.

```bash
D="target.example"; DIR="$HOME/recon/$D/nuclei"; mkdir -p "$DIR"; WEEK=$(date -u +%Y-W%V)
cat "$HOME/recon/$D/subs/$(date -u +%Y%m%d).txt" | httpx -silent | \
  nuclei -severity low,medium,high,critical -jsonl -o "$DIR/${WEEK}.jsonl"
if [ -f "$DIR/last.jsonl" ]; then
  jq -r '"\(.["template-id"])|\(.host)"' "$DIR/${WEEK}.jsonl" | sort -u > /tmp/cur_k.txt
  jq -r '"\(.["template-id"])|\(.host)"' "$DIR/last.jsonl" | sort -u > /tmp/last_k.txt
  comm -13 /tmp/last_k.txt /tmp/cur_k.txt | tee "$DIR/${WEEK}_new.txt"
fi
cp "$DIR/${WEEK}.jsonl" "$DIR/last.jsonl"
```

### Port Diff

```bash
D="target.example"; DIR="$HOME/recon/$D/ports"; mkdir -p "$DIR"; WEEK=$(date -u +%Y-W%V)
naabu -host "$D" -top-ports 1000 -silent | sort -t: -k2 -n > "$DIR/${WEEK}.txt"
[ -f "$DIR/last.txt" ] && comm -13 "$DIR/last.txt" "$DIR/${WEEK}.txt" | tee "$DIR/${WEEK}_new.txt"
cp "$DIR/${WEEK}.txt" "$DIR/last.txt"
```

### Wayback CDX New-URL Check

```bash
D="target.example"; DIR="$HOME/recon/$D/wayback"; mkdir -p "$DIR"; WEEK=$(date -u +%Y-W%V)
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=original&collapse=urlkey&limit=50000" | \
  jq -r '.[1:][] | .[0]' | sort -u > "$DIR/${WEEK}.txt"
[ -f "$DIR/last.txt" ] && comm -13 "$DIR/last.txt" "$DIR/${WEEK}.txt" | tee "$DIR/${WEEK}_new.txt"
cp "$DIR/${WEEK}.txt" "$DIR/last.txt"
```

### Package Registry Version Monitoring

```bash
PKG="target-package"; DIR="$HOME/recon/packages"; mkdir -p "$DIR"
NPM=$(curl -sk "https://registry.npmjs.org/${PKG}/latest" | jq -r '.version // empty')
PYPI=$(curl -sk "https://pypi.org/pypi/${PKG}/json" | jq -r '.info.version // empty')
echo "npm:${NPM:-none} pypi:${PYPI:-none}" > "$DIR/${PKG}_cur.txt"
[ -f "$DIR/${PKG}.txt" ] && diff "$DIR/${PKG}.txt" "$DIR/${PKG}_cur.txt" || true; mv "$DIR/${PKG}_cur.txt" "$DIR/${PKG}.txt"
```

---

## 3. Alert Pipeline Architecture

### Simple: Cron + Diff + Slack Webhook

```bash
WEBHOOK="https://hooks.slack.example/services/YOUR/WEBHOOK/URL"
MSG=$(bash "$HOME/recon/scripts/daily-subdomain-diff.sh" 2>&1)
[ -n "$MSG" ] && curl -sk -X POST "$WEBHOOK" \
  -H 'Content-Type: application/json' -d "$(jq -n --arg t "$MSG" '{text:$t}')"
```

```bash
# crontab
0 6 * * * /home/operator/recon/scripts/alert-slack.sh >> /var/log/recon-alerts.log 2>&1
```

### Medium: JSONL + jq Severity Router + PagerDuty/Slack

```bash
JSONL="$HOME/recon/target.example/nuclei/$(date -u +%Y-W%V)_new.jsonl"
SLACK="https://hooks.slack.example/services/YOUR/WEBHOOK/URL"; PD_KEY="your-pd-key"
# Critical/high -> PagerDuty
jq -c 'select(.info.severity == "critical" or .info.severity == "high")' "$JSONL" | \
while IFS= read -r line; do
  S=$(echo "$line" | jq -r '"\(.["template-id"]) on \(.host) [\(.info.severity)]"')
  curl -sk -X POST "https://events.pagerduty.com/v2/enqueue" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg s "$S" --arg k "$PD_KEY" \
      '{routing_key:$k,event_action:"trigger",payload:{summary:$s,severity:"critical",source:"recon"}}')"
done
# Medium/low -> Slack
jq -c 'select(.info.severity == "medium" or .info.severity == "low")' "$JSONL" | \
while IFS= read -r line; do
  M=$(echo "$line" | jq -r '"\(.["template-id"]) on \(.host)"')
  curl -sk -X POST "$SLACK" -H 'Content-Type: application/json' -d "$(jq -n --arg t "$M" '{text:$t}')"
done
```

### Advanced: GitHub Actions Scheduled Workflow

```yaml
name: Recon Monitor
on:
  schedule: [{cron: '0 6 * * *'}, {cron: '0 8 * * 1'}]
  workflow_dispatch: {}
jobs:
  daily:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bash scripts/daily-subdomain-diff.sh
      - if: hashFiles('new_findings.txt') != ''
        uses: peter-evans/create-issue-from-file@v5
        with: {title: "New subdomains - ${{ github.run_id }}", content-filepath: new_findings.txt, labels: "recon,triage"}
```

---

## 4. False-Positive Tuning

Maintain a suppressions file (JSON). Review quarterly -- context changes make old FPs real findings.

```json
{"suppressions": [
  {"template_id": "tech-detect:waf-detect:cloudflare", "host_pattern": "*.target.example",
   "reason": "Known CDN", "added": "2026-01-15", "review_by": "2026-04-15"}
]}
```

Filter suppressed findings from alert output:

```bash
SUPP="$HOME/recon/target.example/suppressions.json"
INPUT="$HOME/recon/target.example/nuclei/latest.jsonl"
jq -c --slurpfile s "$SUPP" '
  . as $f | ($s[0].suppressions | map(.template_id)) as $ids |
  select([$ids[] | . == $f["template-id"]] | any | not)
' "$INPUT" > "${INPUT%.jsonl}_filtered.jsonl"
```

| Practice | Cadence |
|---|---|
| Review suppressions for stale entries | Quarterly |
| Track FP count per template ID | Every scan cycle |
| Deprioritize templates with >80% FP rate | Monthly |
| Re-enable suppressed after infra changes | On change notification |

---

## 5. Baseline Management

### Initial Capture

```bash
D="target.example"; BASE="$HOME/recon/$D/baselines"; mkdir -p "$BASE"; TS=$(date -u +%Y%m%dT%H%M%SZ)
subfinder -d "$D" -silent -all | sort -u > "$BASE/${TS}_subs.txt"
for RR in A MX TXT NS AAAA CNAME; do dig +short "$D" "$RR" | sort > "$BASE/${TS}_${RR}.txt"; done
naabu -host "$D" -top-ports 1000 -silent | sort > "$BASE/${TS}_ports.txt"
sha256sum "$BASE/${TS}_"* > "$BASE/${TS}.sha256"
```

### Record Schema

```json
{"domain":"target.example","captured_at":"2026-05-29T06:00:00Z","version":3,
 "subdomain_count":147,"open_ports":[80,443,8443,8080],
 "dns_records":{"A":["203.0.113.10"],"MX":["10 mail.target.example."]},
 "cert_names":["target.example","*.target.example"],"sha256":"a1b2c3d4..."}
```

### Refresh Cadence

| Target profile | Subdomains | DNS | Ports |
|---|---|---|---|
| Stable enterprise | Monthly | Monthly | Monthly |
| Fast-moving SaaS | Weekly | Weekly | Weekly |
| Active bug bounty | Weekly | Daily | Weekly |
| M&A due diligence | Start only | Daily | Start + end |

Version in git: `git init && git add . && git commit -m "baseline v1"`. Tag refreshes: `git tag baseline-v2-20260529`.

---

## 6. Long-Running Engagement Patterns

### ASM Contract (Continuous)

| Frequency | Activity |
|---|---|
| Daily | Subdomain diff, CT log poll, DNS record diff |
| Weekly | Full Nuclei sweep, port diff, Wayback new-URL check |
| Monthly | Manual finding review, baseline refresh, suppressions audit |
| Quarterly | Scope review with stakeholder, update target list |

### Bug Bounty (Ongoing)

New-asset detection with fast triage -- every 4h, not daily. Probe new assets within 24h; they ship before hardening catches up.

```bash
0 */4 * * * /home/operator/recon/scripts/daily-subdomain-diff.sh && /home/operator/recon/scripts/ct-monitor.sh
```

### Retainer-Based (Tiered)

| Tier | Scope | Cadence | Deliverable |
|---|---|---|---|
| **Tier 1 -- Passive** | Subdomain + cert + DNS | Daily | Weekly summary email |
| **Tier 2 -- Active** | Tier 1 + Nuclei + ports + Wayback | Weekly | Findings report w/ CVSS/EPSS |
| **Tier 3 -- Comprehensive** | Tier 2 + manual triage + cloud + secrets | Monthly | Full ASM report + risk register |

Tier upgrades triggered by: M&A activity, breach at peer org, new product launch, regulatory audit.

---
