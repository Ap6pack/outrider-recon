# Tool Failure Recovery

> Human-operator reference. Fallback strategies when primary tools
> rate-limit, go down, or get blocked during an engagement.

---

## 1. Subdomain Discovery Fallbacks

**Chain:** subfinder -> amass passive -> manual crt.sh API -> SecurityTrails API

| Priority | Tool / Source         | Type    | Notes                                         |
|----------|-----------------------|---------|-----------------------------------------------|
| Primary  | subfinder             | Passive | Fast, multi-source. First choice always.      |
| Fall 1   | amass enum -passive   | Passive | Slower but deeper. Uses more data sources.    |
| Fall 2   | crt.sh API (manual)   | Passive | Direct CT log query. Free, no key needed.     |
| Fall 3   | SecurityTrails API    | Passive | Requires API key. Reliable but rate-limited.  |

**When crt.sh returns 502:**

Use the 8-source fallback chain documented in recon-asset-discovery section 1.1.
That chain queries VirusTotal, AlienVault OTX, HackerTarget, RapidDNS,
Riddler.io, ThreatCrowd, URLScan, and DNSDumpster in sequence. Merge and
deduplicate results before proceeding.

```bash
# Quick crt.sh check -- if this fails, move to fallback chain
curl -sf "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

---

## 2. Port Scanning Fallbacks

**Chain:** Shodan InternetDB -> Censys -> naabu -> masscan

| Priority | Tool              | Type    | Noise Level | Auth Required       |
|----------|-------------------|---------|-------------|---------------------|
| Primary  | Shodan InternetDB | Passive | None        | No (free endpoint)  |
| Fall 1   | Censys Search     | Passive | None        | Free tier API key   |
| Fall 2   | naabu             | Active  | Moderate    | No                  |
| Fall 3   | masscan           | Active  | Very High   | No (root required)  |

Always prefer passive sources. Active scanning is a last resort and must be
within the engagement's rules of engagement.

**Rate limit handling:**

- Shodan InternetDB: rarely rate-limits, but if it does, wait 10s and retry.
- Censys free tier: 250 queries/month. Track usage. Switch to Shodan if exhausted.
- naabu/masscan: no API limits, but throttle scan rate to avoid triggering
  IDS/IPS on the target side. Use `--rate` flags to control packets per second.

**API key rotation:** Keep 2-3 Censys and Shodan API keys. On HTTP 429,
switch to the next key before backing off.

---

## 3. Breach Data Fallbacks

**Chain:** HudsonRock Cavalier -> HIBP -> DeHashed -> IntelX

| Priority | Source             | Auth           | Rate Limit              |
|----------|--------------------|----------------|-------------------------|
| Primary  | HudsonRock Cavalier| API key        | ~100 req/min            |
| Fall 1   | HIBP               | API key (paid) | 10 req/min (free)       |
| Fall 2   | DeHashed           | API key (paid) | Varies by plan          |
| Fall 3   | IntelX             | API key        | Varies by plan          |

**When HudsonRock rate-limits (HTTP 429):**

1. Back off 60 seconds.
2. Retry up to 3 times with increasing delays (60s, 120s, 180s).
3. If still blocked after 3 retries, fall through to HIBP.
4. Log the partial results already obtained -- do not discard them.

```bash
# Retry logic (pseudocode)
for attempt in 1 2 3; do
  response=$(curl -s -w "%{http_code}" -o body.json "$HUDSONROCK_URL")
  if [ "$response" = "200" ]; then break; fi
  if [ "$response" = "429" ]; then
    sleep $((60 * attempt))
  else
    break  # non-retryable error, fall through
  fi
done
```

---

## 4. DNS / WHOIS Fallbacks

### DNS Resolution

**Chain:** dig -> nslookup -> dnsx

| Priority | Tool      | Best for                              |
|----------|-----------|---------------------------------------|
| Primary  | dig       | Single lookups, detailed output       |
| Fall 1   | nslookup  | Quick checks when dig unavailable     |
| Fall 2   | dnsx      | Bulk resolution of large subdomain lists |

**When DNS resolvers rate-limit:** rotate through public resolvers:

1. `8.8.8.8` / `8.8.4.4` (Google)
2. `1.1.1.1` / `1.0.0.1` (Cloudflare)
3. `9.9.9.9` / `149.112.112.112` (Quad9)

Pass resolver lists to dnsx with `-r resolvers.txt` for automatic rotation.

### WHOIS

**Chain:** whois CLI -> RDAP API -> SecurityTrails historical API

| Priority | Tool / Source            | Notes                                    |
|----------|--------------------------|------------------------------------------|
| Primary  | `whois` CLI              | Works for most TLDs. May be slow.        |
| Fall 1   | RDAP API                 | Structured JSON. Use rdap.org bootstrap. |
| Fall 2   | SecurityTrails historical| Requires API key. Shows historical data. |

---

## 5. Web Probing Fallbacks

**Chain:** httpx -> curl loop -> wget

| Priority | Tool   | Best for                                   |
|----------|--------|--------------------------------------------|
| Primary  | httpx  | Bulk probing, status codes, tech detection |
| Fall 1   | curl   | Single-target checks, custom headers       |
| Fall 2   | wget   | Fallback when curl unavailable             |

### When WAF Blocks Probes

1. **Rotate User-Agent:** switch from default to a common browser UA string.
2. **Add jitter:** randomize delay between requests (1-5s).
3. **Reduce concurrency:** drop httpx threads from 50 to 5-10.
4. **Proxy through clean IP:** route through a VPS or residential proxy that
   has no prior reputation with the target WAF.

### Nuclei Template Failures

- **Syntax errors:** run `nuclei -validate -t template.yaml` to check.
- **Stale templates:** run `nuclei -update-templates` before the engagement.
- **Isolate failures:** run the failing template individually with `-v` for
  verbose output: `nuclei -t specific-template.yaml -u target -v`
- **Template version mismatch:** check that the nuclei binary version matches
  the template pack version.

---

## 6. General Recovery Patterns

### Exponential Backoff

```
delay = min(base * 2^attempt, max_delay) + random_jitter
```

| Parameter      | Recommended Value |
|----------------|-------------------|
| `base`         | 2 seconds         |
| `max_delay`    | 300 seconds       |
| `random_jitter`| 0-1 seconds       |
| `max_attempts` | 5                 |

### API Key Rotation

- Maintain 2-3 API keys per service (Shodan, Censys, SecurityTrails, etc.).
- On HTTP 429, switch to the next key immediately before applying backoff.
- Store keys in a `.keys.json` file outside the engagement directory. Never
  commit API keys to version control.

### IP Rotation

- **SSH SOCKS proxy:** `ssh -D 1080 user@backup-vps` then route tools through
  the SOCKS proxy.
- **Axiom fleet:** spin up disposable VPS instances for distributed scanning.
  Use `axiom-scan` to fan out work across the fleet.
- **Residential proxies:** last resort for heavily geo-restricted or
  reputation-filtered targets. Ensure this is within the rules of engagement.

### Graceful Degradation

When a tool or data source is completely unavailable:

1. Log exactly what could not be checked and why.
2. Note the gap in the report under a "Limitations" section.
3. Document which fallbacks were attempted and their outcomes.
4. Flag the gap to the engagement lead so the client is informed.
5. Schedule a re-check when the tool/service recovers if the engagement
   timeline allows.

Never silently skip a check. An acknowledged gap is better than an incomplete
report that claims full coverage.
