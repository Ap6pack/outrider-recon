# OPSEC Infrastructure as Code

> Human-operator reference. Terraform and Ansible patterns to spin up
> clean engagement infrastructure. Proxy stacks, redirectors, VPS rotation,
> and teardown automation.

---

## 1. Engagement VPS Provisioning

One VPS per engagement. Never share infrastructure across clients.

```hcl
variable "engagement_id" { type = string }
variable "do_token"      { type = string; sensitive = true }
variable "ssh_keys"      { type = list(string) }

provider "digitalocean" { token = var.do_token }

resource "digitalocean_droplet" "scan_box" {
  name      = "recon-${var.engagement_id}"
  image     = "ubuntu-24-04-x64"
  size      = "s-2vcpu-4gb"
  region    = "nyc3"
  ssh_keys  = var.ssh_keys
  tags      = ["engagement:${var.engagement_id}", "disposable"]
  user_data = file("${path.module}/cloud-init.yaml")
}

output "scan_box_ip" { value = digitalocean_droplet.scan_box.ipv4_address }
```

**Cloud-init** -- hardening + tool install:

```yaml
#cloud-config
packages: [ufw, fail2ban, tmux, jq, git, unzip]
runcmd:
  - ufw default deny incoming && ufw allow from YOUR_OPERATOR_IP to any port 22 proto tcp && ufw --force enable
  - for t in subfinder httpx nuclei; do curl -sL "https://github.com/projectdiscovery/${t}/releases/latest/download/${t}_linux_amd64.zip" -o /tmp/${t}.zip && unzip -o /tmp/${t}.zip -d /usr/local/bin/; done
```

---

## 2. SOCKS Proxy Stack

Route all scan traffic through the engagement VPS. Your operator IP never touches the target.

```bash
# Local SOCKS5 tunnel
ssh -D 1080 -N -f -o ServerAliveInterval=60 operator@$(terraform output -raw scan_box_ip)
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me   # verify
```

**Proxychains multi-hop:**

```ini
# /etc/proxychains4.conf
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080        # hop 1: engagement VPS
socks5 10.10.10.1 1080        # hop 2: redirector (optional)
```

**Burp/ZAP upstream proxy:** User Options > Connections > SOCKS Proxy -- `127.0.0.1:1080`, enable DNS over SOCKS.

---

## 3. HTTP Redirector

Target sees the redirector IP, not your scan box. Redirector gets blocked? Spin a new one.

```nginx
server {
    listen 443 ssl;
    server_name redir.engage-domain.example;
    ssl_certificate     /etc/letsencrypt/live/redir.engage-domain.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redir.engage-domain.example/privkey.pem;
    location / {
        proxy_pass https://SCAN_BOX_IP:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_ssl_verify off;
    }
}
```

```bash
certbot --nginx -d redir.engage-domain.example --non-interactive --agree-tos -m ops@firm.example
```

---

## 4. IP Rotation Patterns

**Axiom fleet** -- distribute scans across N disposable nodes:

```bash
axiom-fleet engage-fleet -i 5 -t default
axiom-scan targets.txt -m subfinder -o subs.txt --fleet engage-fleet
axiom-scan targets.txt -m httpx -o httpx.jsonl --fleet engage-fleet
axiom-rm "engage-fleet*" -f
```

**Cloud function rotation** -- each Lambda/Cloud Function invocation gets a different source IP:

```bash
aws lambda invoke --function-name recon-proxy \
  --payload '{"url":"https://target.example","method":"GET"}' /dev/stdout
```

**Tor for passive OSINT** (not active scanning -- exit nodes are widely blocked): `torsocks curl -s "https://crt.sh/?q=%.target.example&output=json" | jq '.[].name_value' | sort -u`

---

## 5. DNS Infrastructure

Fresh domain per engagement. Never reuse your firm's primary domain.

```bash
CF_API="https://api.cloudflare.com/client/v4"; CF_TOKEN="scoped-token"

# Create zone
curl -sX POST "$CF_API/zones" -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"engage-acme.example","plan":{"id":"free"}}' | jq '.result.id'

# Add redirector A record
curl -sX POST "$CF_API/zones/$ZONE_ID/dns_records" -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"A","name":"redir","content":"REDIRECTOR_IP","ttl":300,"proxied":false}'
```

**Wildcard cert:**

```bash
certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cf.ini \
  -d "*.engage-acme.example" -d "engage-acme.example" --non-interactive --agree-tos
```

---

## 6. Ansible Playbook: Full Stack Deploy

```yaml
# site.yml
---
- hosts: all
  become: true
  roles: [base, proxy, scan]

# roles/base/tasks/main.yml
- apt: { name: [ufw, fail2ban, tmux, jq, git, unzip, curl], state: present, update_cache: true }
- ufw: { rule: allow, from_ip: "{{ operator_ip }}", port: "22", proto: tcp }
- ufw: { state: enabled, default: deny }

# roles/proxy/tasks/main.yml
- apt: { name: [nginx, certbot, python3-certbot-nginx], state: present }
- template: { src: redirector.conf.j2, dest: /etc/nginx/sites-enabled/redirector.conf }
  notify: reload nginx

# roles/scan/tasks/main.yml
- get_url: { url: "https://github.com/projectdiscovery/{{ item }}/releases/latest/download/{{ item }}_linux_amd64.zip", dest: "/tmp/{{ item }}.zip" }
  loop: [subfinder, httpx, nuclei]
- unarchive: { src: "/tmp/{{ item }}.zip", dest: /usr/local/bin/, remote_src: yes }
  loop: [subfinder, httpx, nuclei]
```

**Inventory** -- one per engagement:

```ini
[scan]
203.0.113.10 ansible_user=root
[redirector]
203.0.113.20 ansible_user=root
[all:vars]
operator_ip=YOUR_OPERATOR_IP
```

Deploy: `ansible-playbook -i inventories/acme-20260529/hosts site.yml`

---

## 7. Teardown Discipline

No infrastructure survives past the report delivery window.

```bash
#!/usr/bin/env bash
set -euo pipefail
EID="${1:?Usage: teardown.sh <engagement-id>}"

# Wipe logs on remote hosts
ansible all -i "inventories/${EID}/hosts" -m shell \
  -a "journalctl --rotate && journalctl --vacuum-time=1s; rm -rf /var/log/nginx /tmp/*.json*" \
  --become || true

# Terraform destroy
terraform -chdir=engagement-vps destroy -auto-approve \
  -var="engagement_id=${EID}" -var="do_token=${DO_TOKEN}" -var="ssh_keys=${SSH_KEY_IDS}"

# Verify no orphan resources
REMAINING=$(doctl compute droplet list --tag-name "engagement:${EID}" --format ID --no-header)
[ -z "$REMAINING" ] || { echo "[!] ORPHAN DROPLETS: $REMAINING"; exit 1; }

# Purge DNS records
for rid in $(curl -s "$CF_API/zones/$CF_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_TOKEN" | jq -r '.result[].id'); do
  curl -sX DELETE "$CF_API/zones/$CF_ZONE_ID/dns_records/$rid" -H "Authorization: Bearer $CF_TOKEN"
done

# Revoke certs
certbot revoke --cert-name "engage-${EID}.example" --non-interactive || true
echo "[+] Teardown complete: ${EID}"
```

**Post-teardown checklist:** `terraform show` returns empty state. Cloud console shows zero tagged resources. DNS zone purged. Engagement API keys revoked. Certs revoked. Local directory archived and shredded per decommission procedure.

---
