# CDN Bypass & Origin Discovery Techniques

> Human-operator reference. Origin discovery techniques for bypassing CDN/WAF layers.
> Extracted from skill files for clean separation.

---

## DNS History

```bash
# Validin (free)
curl -sk "https://app.validin.com/api/axon/${D}/dns" | jq .
```

---

## Favicon Hash (Shodan)

```bash
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
print(mmh3.hash(codecs.encode(data, 'base64')))"
shodan search "http.favicon.hash:<hash>" --fields ip_str,port,org
```

---

## Host-Header Probe (validate candidate)

```bash
CANDIDATE_IP="203.0.113.42"
curl -sk -m 10 -H "Host: target.example.com" "https://${CANDIDATE_IP}/" -o /tmp/candidate.html
diff <(curl -sk -m 10 https://target.example.com/) /tmp/candidate.html | head -50
```

---

## JARM Fingerprint Clustering

JARM hashes of origin servers differ from CDN edge nodes. Match JARM from Shodan against non-CDN IPs to find the origin.

```bash
# Generate JARM hash for a candidate IP
python3 -m jarm ${CANDIDATE_IP}

# Search Shodan for matching JARM hashes outside CDN ranges
shodan search "ssl.jarm:<origin-jarm-hash> -org:Cloudflare -org:Fastly -org:Akamai" --fields ip_str,port,org,hostnames
```

---

## Certificate SAN Pivot

Enumerate all Subject Alternative Names (SANs) on the CDN certificate. Some SANs may resolve directly to origin IPs that bypass CDN protection.

```bash
# Extract SANs from the CDN-served certificate
echo | openssl s_client -connect target.example:443 -servername target.example 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName | tr ',' '\n' | sed 's/DNS://g' | sort -u

# Resolve each SAN and check if any land outside CDN IP ranges
for san in $(echo | openssl s_client -connect target.example:443 -servername target.example 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName | tr ',' '\n' | sed 's/DNS://g; s/ //g'); do
  echo "${san}: $(dig +short A ${san})"
done
```

---

## Error Page Leakage

Trigger error conditions (oversized headers, malformed requests) that bypass CDN caching layers and reveal origin error pages containing server IPs or internal hostnames.

```bash
# Oversized header — may bypass CDN and hit origin directly
curl -sk -m 10 -H "X-Overflow: $(python3 -c 'print("A"*16000)')" "https://target.example/" -D - | head -30

# Malformed HTTP method — some CDNs pass unrecognized methods through
curl -sk -m 10 -X PURGE "https://target.example/" -D - | head -30

# Malformed Host header — CDN may forward to origin which leaks its identity
curl -sk -m 10 -H "Host: " "https://target.example/" -D - | head -30
```

---

## Email Header Bounce Trick

Send email to a nonexistent address at the target domain. Bounce (NDR) headers sometimes contain the origin MX server IP or internal mail relay hostnames that reveal the origin infrastructure.

```bash
# Send to a guaranteed-nonexistent address and capture the bounce
# (Requires access to a mailbox that receives the NDR)
swaks --to nonexistent-user-xyz@target.example --from test@your-domain.com --server $(dig +short MX target.example | sort -n | head -1 | awk '{print $2}')

# Parse received bounce headers for origin IPs
# Look for: Received: from <internal-hostname> (<origin-ip>)
# Also check: X-Originating-IP, X-Source-IP, X-MS-Exchange-Organization headers
```

---

## Auxiliary Subdomains That Often Skip CDN

```bash
for sub in mail smtp ftp direct origin origin-www old-www noproxy dev staging stg uat; do
  dig +short A "${sub}.${D}"
done
```

---

