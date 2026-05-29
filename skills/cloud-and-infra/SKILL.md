---
name: cloud-and-infra
description: "Cloud-native service fingerprints, Kubernetes/container exposure, CI/CD platform exposure, TLS deep audit, and favicon hash pivot for authorized infrastructure recon."
version: 1.1.0
triggers:
  - cloud native fingerprint
  - Lambda function URL
  - Cloud Run
  - kubernetes exposure
  - kubelet
  - etcd
  - CI CD exposure
  - Jenkins recon
  - GitLab self-hosted
  - GitHub Actions secrets
  - TLS deep audit
  - JA3 JA4
  - container registry
  - Docker API
  - Argo CD
  - favicon hash
---

# Cloud & Infrastructure OSINT

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** Cloud-native service fingerprinting, Kubernetes/container exposure, CI/CD platform exposure, TLS deep audit, or container registry leak hunting is needed.

**Execute:**
1. For each discovered subdomain/IP, match against cloud-native URL patterns (§1). Classify provider and service type.
2. Check public-vs-auth-required on each cloud function endpoint (HEAD/GET).
3. For K8s/container exposure: probe ports from §2 table (Docker 2375/2376, kubelet 10250, etcd 2379, K8s API 6443/8443). Anonymous access = CRITICAL.
4. Check CI/CD platforms (§3) for unauthenticated access.
5. Run TLS deep audit (§4) on every HTTPS endpoint in scope.
6. Check public container registries (§2) for target-owned images.
7. For each finding, emit per `osint-methodology` §3 schema.

**Output:** Infrastructure findings with provider, service type, auth posture, severity. All per `osint-methodology` §3 schema.

**Severity rules:** Inline per section tables. Docker API unencrypted = CRITICAL. Open kubelet = CRITICAL. Open etcd = CRITICAL. K8s API anonymous = HIGH. TLS 1.0/1.1 = MEDIUM.

**Gating rules:** Active port probing is HIGH detectability — confirm authorization. Container image pulls generate logs — note detectability.

**Chain to:** Feed discovered cloud endpoints to `web-surface` for HTTP checks. Feed K8s findings to `analysis-and-reporting` for attack-path hints. For ASN/BGP lookups, use `recon-asset-discovery`.

---

## 1. Cloud-Native Service Fingerprints

| Provider | URL pattern | Notes |
|---|---|---|
| **AWS Lambda Function URL** | `*.lambda-url.<region>.on.aws` | Direct invocation; check IAM auth posture |
| **AWS App Runner** | `*.<region>.awsapprunner.com` | Managed container |
| **AWS API Gateway** | `*.execute-api.<region>.amazonaws.com` | REST/HTTP/WebSocket; check authorizer |
| **AWS CloudFront** | `d{14}\.cloudfront\.net` | Distribution; find origin via `docs/methods/cdn-bypass-techniques.md` |
| **AWS ALB / ELB** | `*.elb.<region>.amazonaws.com` | Behind = EC2 / ECS |
| **AWS Amplify** | `*.amplifyapp.com` | Static + Lambda backend |
| **Google Cloud Run** | `*.run.app` (and `*.<region>.run.app`) | Check public-vs-IAM auth |
| **Google Cloud Functions** | `*.cloudfunctions.net` | Serverless |
| **Google App Engine** | `*.appspot.com` | Older serverless |
| **Azure Functions** | `*.azurewebsites.net` | Function App; also App Service |
| **Azure Container Apps** | `*.azurecontainerapps.io` | Containers |
| **Vercel** | `*.vercel.app`, `*.now.sh` (legacy) | Frontend + serverless |
| **Netlify** | `*.netlify.app`, `*.netlify.com` | Frontend + functions |
| **Cloudflare Workers** | `*.workers.dev` | Edge functions |
| **Cloudflare Pages** | `*.pages.dev` | Static + functions |
| **Heroku** | `*.herokuapp.com` | Dynos |
| **Render** | `*.onrender.com` | Container/static |
| **Railway** | `*.railway.app` | App platform |
| **DigitalOcean App Platform** | `*.ondigitalocean.app` | Static + container |

**Per-platform checks:**
- Confirm public vs auth-required (HEAD / GET).
- Check CORS posture.
- Lambda Function URLs / Cloud Run / Cloud Functions: anonymous invocation = HIGH finding.
- Static + functions hybrids (Vercel/Netlify): function paths usually `/api/*`; enumerate via JS extraction.

---

## 2. Container & Kubernetes Exposure

| Target | Port | Probe | Severity |
|---|---|---|---|
| **Docker API (unencrypted)** | 2375 | `curl -sk -m 5 http://${IP}:2375/v1.40/info` | CRITICAL |
| **Docker API (TLS)** | 2376 | `curl -sk -m 5 https://${IP}:2376/v1.40/info` | HIGH |
| **Kubernetes API server** | 6443 / 8443 | `curl -sk -m 5 https://${IP}:6443/api` | HIGH if anonymous non-403 |
| **kubelet** | 10250 (HTTPS) | `curl -sk -m 5 https://${IP}:10250/pods` | CRITICAL (no auth = pod exec) |
| **etcd** | 2379 (client) | `curl -sk -m 5 https://${IP}:2379/v2/keys/` | CRITICAL (cluster state + secrets) |
| **Kubernetes Dashboard** | 8001 / 9090 / 30000+ | `curl -sk -m 5 http://${IP}:8001/api/v1/namespaces/kube-system/services/kubernetes-dashboard` | HIGH |
| **kube-controller-manager** | 10257 | `curl https://${IP}:10257/metrics` | MEDIUM |
| **kube-scheduler** | 10259 | `curl https://${IP}:10259/metrics` | MEDIUM |
| **Helm Tiller** (Helm 2, deprecated but found) | 44134 | `helm --host ${IP}:44134 list` | HIGH |

**Container registries to check for leaks:**

| Registry | Search pattern |
|---|---|
| Docker Hub | `https://hub.docker.com/search?q=<target-keyword>&type=image` |
| Quay (Red Hat) | `https://quay.io/search?q=<target-keyword>` |
| GitHub Container Registry | `https://api.github.com/orgs/<org>/packages?package_type=container` |
| Amazon ECR Public | `https://gallery.ecr.aws/?searchTerm=<keyword>` |
| Google Container Registry (GCR) | `https://gcr.io/v2/<project-id>/tags/list` (also try `us.gcr.io`, `eu.gcr.io`, `asia.gcr.io`) |
| Azure Container Registry (ACR) | `https://<registry>.azurecr.io/v2/_catalog` (anonymous pull if enabled) |

**Per-image scan workflow:**
```bash
docker pull <registry>/<image>:<tag>
docker save <image> -o /tmp/img.tar
# Extract layers; run secret catalog over files
docker history <image>   # inspect build args + COPY of secrets
```

---

## 3. CI/CD Platform Exposure

| Platform | Common exposure | Probe |
|---|---|---|
| **Jenkins** | `/script` (Groovy console = RCE if no auth), `/asynchPeople/` | `curl -sk -m 10 "${T}/script"` |
| **GitLab self-hosted** | Version in HTML; `/api/v4/version` | `curl -sk -m 10 "${T}/api/v4/version"` |
| **TeamCity** | `/login.html`; CVE-2024-27198 (KEV) | `curl -sk -m 10 "${T}/login.html" \| grep -i TeamCity` |
| **Argo CD** | `/api/version`; anonymous-auth posture | `curl -sk -m 10 "${T}/api/version"` |
| **Bamboo** | `/rest/api/latest/info` | `curl -sk -m 10 "${T}/rest/api/latest/info"` |
| **Drone CI** | `/api/info` | `curl -sk -m 10 "${T}/api/info"` |
| **Spinnaker** | `/gate/info`, `/applications` | `curl -sk -m 10 "${T}/gate/info"` |
| **CircleCI** | `/api/v2/me` (token leak → project enum), public build logs | `curl -sk -m 10 "${T}/api/v2/me" -H "Circle-Token: ${TOKEN}"` |

**GitHub Actions secret-leak anti-patterns:**
```yaml
# Anti-pattern: secret echoed to log
run: echo "${{ secrets.MY_API_KEY }}"

# Anti-pattern: pull_request_target with fork code checkout (CVE class)
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out fork code with secrets in env
```

---

## 4. TLS Deep Audit

Beyond cert SAN + JARM — inspect cipher suites, protocols, and config quality.

```bash
# sslyze (most thorough — install: see docs/reference/tooling-install.md)
sslyze --regular target.example:443
sslyze --json_out=tls.json target.example:443

# testssl.sh (thorough + readable)
docker run --rm -ti drwetter/testssl.sh https://target.example
testssl.sh --jsonfile-pretty=tls-report.json target.example:443

# nmap (lighter)
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.example
```

**Issues to check:**

| Issue | Severity |
|---|---|
| TLS 1.0 / 1.1 supported | MEDIUM (PCI-DSS forbids TLS 1.0) |
| SSL 3.0 / 2.0 supported | HIGH |
| Weak ciphers (RC4, 3DES, CBC modes) | MEDIUM |
| Anonymous DH | HIGH |
| Weak key size (<2048 RSA, <256 ECDSA) | HIGH |
| Heartbleed (CVE-2014-0160) | CRITICAL |
| ROBOT (CVE-2017-13099) | HIGH |
| Ticketbleed (CVE-2016-9244) | HIGH (F5-specific) |
| HSTS not present on /login | HIGH |
| Self-signed cert on production | MEDIUM |
| Expired cert | MEDIUM |

**JA3/JA4 reference databases:**
- [ja3er.com](https://ja3er.com) — JA3 → client-software mapping.
- Shodan `ssl.jarm:<hash>` to find shared infrastructure / origin candidates.

---

## 5. Favicon mmh3 Hash Pivot

```bash
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
print(mmh3.hash(codecs.encode(data, 'base64')))"
shodan search "http.favicon.hash:<hash>" --fields ip_str,port,org
```

---

> **Note:** For ASN/BGP and internet measurement, see `recon-asset-discovery`. For reverse DNS sweep and IPv6 enumeration scripts, see `docs/methods/active-sweep-scripts.md`.
