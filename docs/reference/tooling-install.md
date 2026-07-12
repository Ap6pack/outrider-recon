# Tooling Quick-Install

> Installation commands for all recommended tools, organized by category.
> Extracted from skill files for clean separation.

---

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/d3mondev/puredns/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# HTTP probing & enrichment
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
go install github.com/michenriksen/aquatone@latest

# Vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -ut
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Content discovery
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
cargo install feroxbuster

# JS / endpoint extraction
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/subjs@latest
go install github.com/jaeles-project/gospider@latest
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip install -r requirements.txt

# Secret scanners
go install github.com/trufflesecurity/trufflehog@latest
go install github.com/zricethezav/gitleaks/v8@latest

# Wayback
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Cloud / AWS
pip install awscli s3scanner sslyze
git clone https://github.com/initstring/cloud_enum && cd cloud_enum && pip install -r requirements.txt
git clone https://github.com/aquasecurity/cloudsploit && cd cloudsploit && npm install

# Identity / SSO
git clone https://github.com/gremwell/o365enum
git clone https://github.com/knavesec/CredMaster

# GraphQL
pip install clairvoyance graphql-cop

# Mobile
pip install apkleaks androguard
pip install google-play-scraper

# TLS / cert
pip install pyjarm
go install github.com/lanrat/certgraph@latest
git clone --depth 1 https://github.com/drwetter/testssl.sh.git

# Misc utilities
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/hakluke/hakrawler@latest
sudo apt install jq

# Frameworks / orchestration
git clone https://github.com/six2dez/reconftw && cd reconftw && ./install.sh
git clone https://github.com/pry0cc/axiom && cd axiom && ./interact/axiom-configure
```

**Full PD toolkit:** `go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all`

---
