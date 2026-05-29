# Active Sweep Scripts

> Human-operator reference. Bash/PowerShell scripts for subdomain prefix sweeps,
> reverse DNS sweeps, ASN/BGP lookups, and IPv6 enumeration.
> Extracted from skill files for clean separation.

---

## Subdomain Common-Prefix Active Sweep

Passive enum misses 20–40% of high-value subdomains. Always pair with active prefix probe (detectability: low — single A-record query per host).

```bash
D="target.example"
for p in www mail webmail owa autodiscover ftp vpn sslvpn gateway api app portal login sso idp iam identity accounts oauth auth adfs admin intranet hr sap erp crm support help status grafana kibana docs wiki jira jenkins gitlab dev test staging stg qa uat sandbox preprod preview careers jobs eapps old legacy beta tender suppliers procurement; do
  IP=$(dig +short A "$p.$D" | head -1)
  [ -n "$IP" ] && echo "$p.$D -> $IP"
done
```

PowerShell equivalent:
```powershell
$D = "target.example"
$prefixes = @("www","mail","webmail","owa","autodiscover","ftp","vpn","sslvpn","gateway","api","app","portal","login","sso","idp","iam","identity","accounts","oauth","auth","adfs","admin","intranet","hr","sap","erp","crm","support","help","status","grafana","kibana","docs","wiki","jira","jenkins","gitlab","dev","test","staging","stg","qa","uat","sandbox","preprod","preview","careers","jobs","eapps","old","legacy","beta","tender","suppliers","procurement")
foreach ($p in $prefixes) {
  $r = Resolve-DnsName "$p.$D" -Type A -ErrorAction SilentlyContinue
  if ($r) { $ips = ($r | ? {$_.IPAddress}).IPAddress -join ","; "$p.$D -> $ips" }
}
```

**Wordlist sources:**

| Source | URL |
|---|---|
| **Assetnote** | `https://wordlists.assetnote.io/` — best-curated; per-CMS/framework |
| **SecLists** | `https://github.com/danielmiessler/SecLists` — `Discovery/DNS/subdomains-top1million-110000.txt` |
| **jhaddix all.txt** | `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056` |

---

## ASN/BGP Bulk Lookup Recipes

```bash
# Cymru bulk WHOIS (fastest; no rate-limit; no key)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43

# RIPEstat (free; ~1 req/sec polite)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'

# bgp.tools (free; light rate-limit)
curl -sk -A "osint-recon/1.0 (contact@example.com)" "https://bgp.tools/api/ip/8.8.8.8" | jq .
```

**Note:** `bgpview.io` API has aggressive undocumented rate limits (~1 req/min/IP); not suitable for bulk.

---

## Reverse DNS Sweep & IPv6 Enumeration

> Reverse DNS and IPv6 enumeration scripts for active sweep operations.

```bash
# Single /24
for i in $(seq 1 254); do
  IP="203.0.113.$i"
  PTR=$(dig +short -x $IP)
  [ -n "$PTR" ] && echo "$IP -> $PTR"
done

# Larger range with parallelism
prips 203.0.113.0/22 | xargs -I {} -P 50 sh -c 'PTR=$(dig +short -x {}); [ -n "$PTR" ] && echo "{} -> $PTR"'

# zdns (faster for large ranges)
prips 203.0.113.0/22 | zdns PTR

# masscan + banner-grab
sudo masscan -p80,443 203.0.113.0/22 --rate=1000 --banners -oX masscan.xml
```

**IPv6 enumeration:**
```bash
# AAAA records for every discovered subdomain
for sub in $(cat all-subs.txt); do
  AAAA=$(dig +short AAAA $sub)
  [ -n "$AAAA" ] && echo "$sub -> $AAAA"
done
# IPv6 brute-force is infeasible (2^64 host bits); instead: extract prefixes from ASN allocation
whois -h whois.cymru.com " -v target.example.com"
```

**BGP route observation:**
- [RouteViews](http://archive.routeviews.org/) — historical BGP routing table snapshots.
- [RIPE RIS](https://ris.ripe.net/) — route collectors.

---

