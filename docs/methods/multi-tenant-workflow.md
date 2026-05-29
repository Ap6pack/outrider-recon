# Multi-Tenant Engagement Workflow

> Human-operator reference. Managing concurrent ASM/red-team engagements
> without crossing wires. Designed for MSSPs and consultancies running
> 10-50+ simultaneous targets.

---

## 1. Directory Convention

One directory per engagement. No exceptions.

```
engagements/
  acme-corp/2026-05-15/
    .engagement.json  scope.json  .env
    evidence/  findings/  baselines/  reports/  sidecars/
  globex-intl/2026-05-20/
    ...
```

`.engagement.json` anchors every engagement:

```json
{
  "engagement_id": "acme-corp-20260515", "client": "Acme Corp",
  "scope_ref": "scope.json", "start_date": "2026-05-15", "end_date": "2026-06-15",
  "status": "active", "operator": "jdoe",
  "rules_of_engagement": {
    "testing_window": "Mon-Fri 0800-1800 UTC", "no_dos": true,
    "notify_on_critical": "security@acme.example"
  }
}
```

---

## 2. Scope Isolation

Every engagement gets a `scope.json`. Nothing runs without a scope check.

```json
{
  "in_scope": {
    "domains": ["acme.example", "*.acme.example", "acme-corp.io"],
    "ip_ranges": ["203.0.113.0/24", "198.51.100.0/24"]
  },
  "exclusions": { "domains": ["payments.acme.example"], "ip_ranges": ["203.0.113.200/32"] }
}
```

Pre-flight check -- source in every session:

```bash
scope_check() {
  local target="$1" sf="$2"
  [ -z "$target" ] || [ -z "$sf" ] && { echo "FAIL: scope_check <target> <scope.json>" >&2; return 1; }
  [ -f "$sf" ] || { echo "FAIL: $sf not found" >&2; return 1; }
  jq -e --arg t "$target" '.exclusions.domains//[]|any(.==$t)' "$sf" >/dev/null 2>&1 \
    && { echo "BLOCKED: $target excluded" >&2; return 1; }
  jq -e --arg t "$target" '
    .in_scope.domains//[]|any(if startswith("*.") then ($t|endswith(ltrimstr("*"))) else .==$t end)
  ' "$sf" >/dev/null 2>&1 && { echo "OK: $target in scope"; return 0; }
  if echo "$target" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "$target" | grepcidr "$(jq -r '.in_scope.ip_ranges[]?' "$sf"|tr '\n' ' ')" \
      >/dev/null 2>&1 && { echo "OK: $target in scope (IP)"; return 0; }
  fi
  echo "BLOCKED: $target NOT in scope" >&2; return 1
}
```

**Hard rule:** every probe calls `scope_check` before any network request. Fail = abort.

---

## 3. Credential and Token Isolation

Per-engagement `.env` at `engagements/{slug}/{date}/.env`. Gitignore: `engagements/**/.env`.

```bash
# engagements/acme-corp/2026-05-15/.env
SHODAN_API_KEY=aaaa1111bbbb2222cccc3333
SECURITYTRAILS_KEY=xxxx-yyyy-zzzz
HUNTER_API_KEY=hk_live_abc123
CENSYS_API_ID=aaaaaaaa-bbbb-cccc-dddd
VIRUSTOTAL_KEY=vt_999888777
```

Switch context:

```bash
activate_engagement() {
  local slug="$1" date="$2" edir="engagements/${slug}/${date}"
  [ -f "${edir}/.env" ] || { echo "FAIL: no .env at ${edir}" >&2; return 1; }
  set -a; source "${edir}/.env"; set +a
  export ENGAGEMENT_DIR="$(pwd)/${edir}" ENGAGEMENT_ID="${slug}-${date//\-/}"
  echo "Activated: $ENGAGEMENT_ID"
}
```

Rotate shared API tokens every 90 days or on engagement close, whichever first.

---

## 4. Output Segregation

All tool output lands inside `$ENGAGEMENT_DIR`. Never write to a shared location.

```bash
httpx -l targets.txt -sc -title -json -o "${ENGAGEMENT_DIR}/findings/httpx-$(date -u +%Y%m%d).jsonl"
nuclei -l targets.txt -jsonl -o "${ENGAGEMENT_DIR}/findings/nuclei-$(date -u +%Y%m%d).jsonl"
```

Every JSONL record carries `engagement_id`:

```json
{"engagement_id":"acme-corp-20260515","ts":"2026-05-16T14:30:00Z","tool":"nuclei","template":"cves/CVE-2024-3400","host":"vpn.acme.example","severity":"critical"}
```

Sidecars (Shodan enrichment, screenshots, WHOIS) go to `sidecars/`. Portfolio merge (requires `portfolio_reporting: true` in ROE):

```bash
OUTPUT="reports/portfolio-$(date -u +%Y%m%d).jsonl"; > "$OUTPUT"
for edir in engagements/*/*/; do
  meta="${edir}.engagement.json"; [ -f "$meta" ] || continue
  jq -r '.rules_of_engagement.portfolio_reporting//"false"' "$meta" | grep -q true || continue
  cat "${edir}findings/"*.jsonl 2>/dev/null >> "$OUTPUT"
done; echo "Merged $(wc -l < "$OUTPUT") records"
```

---

## 5. Parallel Execution

**GNU parallel** -- same scan across all active engagements:

```bash
find engagements -name ".engagement.json" -exec \
  jq -r 'select(.status=="active") | input_filename' {} \; | \
  while read meta; do jq -r '.in_scope.domains[]' "$(dirname "$meta")/scope.json"; done | \
  parallel -j 4 --tag 'subfinder -d {} -silent'
```

**Tmux session-per-engagement:**

```bash
for edir in engagements/*/*/; do
  slug=$(basename "$(dirname "$edir")")
  tmux new-session -d -s "$slug" "cd $edir && source .env && bash"
done
```

**Per-target rate limiting** -- each engagement gets its own cap, never a global limit. **Axiom fleet** -- spin up cloud workers per engagement:

```bash
axiom-fleet acme-scan -i 3 && axiom-fleet globex-scan -i 3
axiom-scan targets.txt -m subfinder -o "${ENGAGEMENT_DIR}/findings/subs.txt" --fleet acme-scan
```

---

## 6. Reporting and Delivery

```bash
./scripts/generate-report.sh "${ENGAGEMENT_DIR}" \
  --template templates/asm-monthly.md \
  --output "${ENGAGEMENT_DIR}/reports/report-$(date -u +%Y%m%d).pdf"
```

Diff report for continuous engagements:

```bash
diff_findings() {
  local prev="$1" curr="$2"
  comm -13 <(jq -r '[.host,.template]|join("|")' "$prev"|sort) \
           <(jq -r '[.host,.template]|join("|")' "$curr"|sort) > "${ENGAGEMENT_DIR}/reports/new.txt"
  comm -23 <(jq -r '[.host,.template]|join("|")' "$prev"|sort) \
           <(jq -r '[.host,.template]|join("|")' "$curr"|sort) > "${ENGAGEMENT_DIR}/reports/resolved.txt"
  echo "New: $(wc -l < "${ENGAGEMENT_DIR}/reports/new.txt") | Resolved: $(wc -l < "${ENGAGEMENT_DIR}/reports/resolved.txt")"
}
```

**Sanitization checklist (before every delivery):** `grep -rn` for other client slugs (zero matches). Verify every IP/domain exists in `scope.json`. Strip operator notes (`TODO|FIXME|INTERNAL`). Confirm no API keys in deliverables. Scrub PDF metadata: `exiftool -all= report.pdf`. Second operator reviews final artifact.

---

## 7. Decommission

```bash
decommission_engagement() {
  local edir="$1"
  ls "${edir}"/reports/*.pdf >/dev/null 2>&1 || { echo "FAIL: no report delivered"; return 1; }
  tar czf - "${edir}" | gpg --symmetric --cipher-algo AES256 \
    -o "${edir}-archive-$(date -u +%Y%m%d).tar.gz.gpg"
  gpg --decrypt "${edir}-archive-"*.tar.gz.gpg | tar tzf - >/dev/null \
    || { echo "FAIL: bad archive"; return 1; }
  find "${edir}" -type f -exec shred -vfz -n 3 {} \;
  rm -rf "${edir}"
  jq --arg d "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '. + {status:"decommissioned",destruction_date:$d}' \
    "${edir}/.engagement.json" > "$(dirname "${edir}")/closed-$(basename "${edir}").json"
}
```

**Retention:** follow client contract; default 90 days post-delivery, then destroy.

**Cryptographic destruction** for encrypted volumes:

```bash
sudo cryptsetup luksClose engagement-vol
sudo dd if=/dev/urandom of=/dev/sdX bs=1M count=16    # wipe LUKS header
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | destroyed | /dev/sdX | $(whoami)" >> destruction-log.txt
```

---
