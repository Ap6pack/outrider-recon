# Tool Directory

> Consolidated tool recommendations organized by category.
> Extracted from skill files for clean separation.

---

## AI-Assisted OSINT

> **Warning:** Never paste PII, sensitive IOCs, or unique pivots into cloud LLMs.

| Tool                                         | Strength                                                     |
| -------------------------------------------- | ------------------------------------------------------------ |
| [ChatGPT](https://chat.openai.com/) (paid)   | Log parsing, dataset analysis, Code Interpreter for CSV/JSON |
| [Claude](https://claude.ai/) (paid)          | 200K-token context for large doc dumps + report synthesis    |
| [Gemini](https://gemini.google.com/)         | Long-context; Deep Research mode with citations              |
| [Perplexity Pro](https://www.perplexity.ai/) | Real-time web search + reasoning                             |

**Local / privacy-preserving:** [Ollama](https://ollama.com/), [LM Studio](https://lmstudio.ai/).

---

## Username & Email Investigation

| Tool                                                                      | Purpose                                |
| ------------------------------------------------------------------------- | -------------------------------------- |
| [Sherlock](https://github.com/sherlock-project/sherlock)                  | Username search across social networks |
| [Maigret](https://github.com/soxoj/maigret)                               | Profile collector by username          |
| [What's My Name](https://whatsmyname.app/)                                | Username search                        |
| [Holehe](https://github.com/megadose/holehe)                              | Email registration check               |
| [Epieos](https://epieos.com/)                                             | Email pivots and metadata              |
| [OSINT Industries](https://osint.industries/)                             | Email/username/phone lookups           |
| [Hunter.io](https://hunter.io/)                                           | Domain → emails                        |
| [EmailRep](https://emailrep.io/)                                          | Email reputation                       |
| [RocketReach](https://rocketreach.co/) / [Apollo](https://www.apollo.io/) | Email enrichment + pattern guessing    |

---

## People Search

- [TruePeopleSearch](https://www.truepeoplesearch.com/) — free U.S. people search.
- [WhitePages](https://www.whitepages.com/), [Spokeo](https://www.spokeo.com/), [Webmii](https://webmii.com/), [Pipl](https://pipl.com/) (paid).
- [FaceCheck](https://facecheck.id/) / [FaceSeek](https://faceseek.online/) — reverse face search.

---

## Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/) — caller ID + spam blocking.
- [ThatsThem](https://thatsthem.com/) — reverse phone search.
- [Infobel](https://infobel.com/) — non-USA phone search.
- [FreeCarrierLookup](https://freecarrierlookup.com/) — carrier/type (US).

---

## Social Media

| Platform       | Tool                                                                                                       |
| -------------- | ---------------------------------------------------------------------------------------------------------- |
| Instagram      | [Picuki](https://www.picuki.com/) — profile view without account                                           |
| X/Twitter      | [snscrape](https://github.com/snscrape/snscrape) — preferred CLI scraper                                   |
| Facebook       | [Graph Search](https://inteltechniques.com/tools/Facebook.html), [sowsearch.info](https://sowsearch.info/) |
| YouTube/Twitch | [Social Blade](https://socialblade.com/) — analytics                                                       |
| TikTok         | [Tokboard](https://tokboard.com/) — trends + profile analytics                                             |
| Reddit         | [Reveddit](https://www.reveddit.com/) — removed content                                                    |
| Bluesky        | [Firesky](https://firesky.tv/) — real-time firehose                                                        |
| Mastodon       | [FediSearch](https://fedisearch.skorpil.cz/) — cross-instance                                              |
| Faces          | [Search4Faces](https://search4faces.com/)                                                                  |

---

## Threat Intel & IOCs

- CERT advisories: CISA/NSA/CSA, CERT-EU, NCSC-UK, JPCERT/CC, CERT-UA.
- [OpenCTI](https://www.opencti.io/) — CTI knowledge graph.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) — malware families, YARA, references.
- [MISP Project](https://www.misp-project.org/) — threat sharing platform; public MISP feeds.
- [ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/).
- [MalwareBazaar](https://bazaar.abuse.ch/) — hash-based sample sharing.
- [PhishTank](https://www.phishtank.com/), [OpenPhish](https://openphish.com/).

### Malware Analysis & Sandboxes

- Static: [pefile](https://github.com/erocarrera/pefile), [FLOSS](https://github.com/mandiant/flare-floss), [capa](https://github.com/mandiant/capa).
- Similarity: SSDEEP, TLSH.
- Sandboxes: [ANY.RUN](https://any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), [CAPE](https://capesandbox.com/), [Tria.ge](https://tria.ge/).
- Intelligence: [Intezer](https://analyze.intezer.com/) (code reuse), [VirusTotal](https://www.virustotal.com/) — **caution: uploads become public**.
- TLS: [JA3](https://github.com/salesforce/ja3), [JA4](https://github.com/FingerprinTLS/ja4).

### Vulnerability Prioritization Data Sources

| Source                         | URL                                                                                              | What it tells you                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| **NVD**                        | `<https://nvd.nist.gov/vuln/search`> (or API `services.nvd.nist.gov/rest/json/cves/2.0`)         | Base CVE catalog with CVSS v2/v3 scores.                         |
| **EPSS**                       | `<https://www.first.org/epss/`> (CSV at `<https://epss.cyentia.com/epss_scores-current.csv.gz`>) | 0.0-1.0 probability of exploit in next 30 days. Updated daily.   |
| **CISA KEV**                   | `<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`>          | CVEs proven exploited in the wild + federal-agency due-by dates. |
| **ExploitDB**                  | `<https://www.exploit-db.com/`;> offline DB via `searchsploit`                                   | POC code presence (Metasploit, Python, shell).                   |
| **Metasploit module catalog**  | `<https://www.rapid7.com/db/modules/`> (or `msfconsole > search cve:CVE-2024-XXXX`)              | Automation availability.                                         |
| **InTheWild.io**               | `<https://inthewild.io/`>                                                                        | Community-curated "actively exploited" tracker.                  |
| **OpenCVE**                    | `<https://www.opencve.io/`>                                                                      | Timeline + watchlist + alerts.                                   |
| **Trickest CVE → POC mapping** | `<https://github.com/trickest/cve`>                                                              | Auto-generated CVE → public POC repo links.                      |
| **GitHub Security Advisories** | `<https://github.com/advisories`>                                                                | Per-language / per-ecosystem advisories.                         |
| **MITRE CVE List**             | `<https://cve.mitre.org/cve/`>                                                                   | Official CVE registry.                                           |
| **VulnDB**                     | `<https://vulndb.cyberriskanalytics.com/`>                                                       | Paid; commercial enrichment.                                     |
| **OSV.dev**                    | `<https://osv.dev/`>                                                                             | Open-source vulnerability DB; JSON API.                          |
| **Vulncheck KEV**              | `<https://vulncheck.com/kev`>                                                                    | Expanded KEV feed (more than CISA).                              |
| **Tenable Research**           | `<https://www.tenable.com/research`>                                                             | Tenable's CVE detail enrichment.                                 |
| **Qualys ThreatPROTECT**       | `<https://threatprotect.qualys.com/`>                                                            | Qualys' threat-context enrichment.                               |

---

## Cryptocurrency OSINT

- [Blockchain.com](https://www.blockchain.com/explorer), [Etherscan](https://etherscan.io/), [Solscan](https://solscan.io/).
- [Blockchair](https://blockchair.com/) — multi-chain block explorer.
- [BSCScan](https://bscscan.com/) — BNB Chain explorer.
- [OKLink](https://www.oklink.com/) — multi-chain (freemium).
- [Arkham](https://www.arkhamintelligence.com/) — multichain, entity labels, graphs.
- [MetaSleuth](https://metasleuth.io/) — visual flow.
- [Breadcrumbs](https://www.breadcrumbs.app/) — visual graphing + labels (freemium).
- [Chainalysis](https://www.chainalysis.com/) / [Crystal Blockchain](https://crystalblockchain.com/) — pro analytics.
- [Bubblemaps](https://bubblemaps.io/) — holder concentration.
- [Whale Alert](https://whale-alert.io/) — large transaction monitoring.
- [GraphSense](https://graphsense.info/) — open-source crypto analytics.
- [Nansen](https://www.nansen.ai/) — Smart Money labels (paid).
- [Dune](https://dune.com/) — custom queries.
- [Token Sniffer](https://tokensniffer.com/) — honeypot/scam detection.

### L2 / Rollup Explorers

| L2            | Explorer                                                               | Notes                                      |
| ------------- | ---------------------------------------------------------------------- | ------------------------------------------ |
| Arbitrum      | [Arbiscan](https://arbiscan.io/)                                       | Optimistic rollup; 7-day challenge window. |
| Optimism      | [Optimistic Etherscan](https://optimistic.etherscan.io/)               | Optimistic rollup; 7-day challenge window. |
| Base          | [BaseScan](https://basescan.org/)                                      | OP Stack.                                  |
| Blast         | [Blastscan](https://blastscan.io/)                                     | OP Stack derivative.                       |
| Scroll        | [Scrollscan](https://scrollscan.com/)                                  | zkEVM.                                     |
| zkSync Era    | [zkSync Era Block Explorer](https://explorer.zksync.io/)               | zkRollup; faster finality.                 |
| Polygon zkEVM | [PolygonScan zkEVM](https://zkevm.polygonscan.com/)                    | zkEVM.                                     |
| StarkNet      | [Voyager](https://voyager.online/), [StarkScan](https://starkscan.co/) | Cairo VM; different address derivation.    |
| Cross-L2      | [L2Beat](https://l2beat.com/)                                          | Risk framework + TVL comparison.           |

### NFT / Exchange / Bridges

- [OpenSea](https://opensea.io/), [NFTScan](https://www.nftscan.com/), [DappRadar](https://dappradar.com/), [CoinGecko](https://www.coingecko.com/), [CoinMarketCap](https://coinmarketcap.com/), [Glassnode](https://glassnode.com/).
- Bridges: [Socketscan](https://socketscan.io/), [L2Beat Bridges](https://l2beat.com/bridges), [Pulsy](https://pulsy.io/).

---

## Telegram & Messaging Intelligence

- [TGStat](https://tgstat.com/) — channel analytics + search.
- [Telemetr](https://telemetr.io/) — channel growth, overlaps, forwards.
- [Combot](https://combot.org/) — group analytics (partial paid).
- [TelegramDB Search Bot](https://t.me/TGdb_bot) — basic Telegram OSINT.
- [Discord ID](https://discord.id/) — basic Discord account info.
- [Sogou Weixin search](https://weixin.sogou.com/) — WeChat Official Accounts.
- View public Telegram channels: `<https://t.me/s/<channel>>`.
- Google: `site:t.me "{target}"`.

---

## Workspace Discovery (Slack / Discord)

### Public Slack Directories

- [Slofile](https://slofile.com/), [Slacklist](https://slacklist.info/) — public Slack workspace directories.

### Discord Server Directories

- [DiscordServers.com](https://discordservers.com/), [Discord.me](https://discord.me/), [Top.gg](https://top.gg/) — Discord server directories.

---

## Job Posting Tech-Stack Analysis

**ATS Platforms:**

| Platform        | URL                                 |
| --------------- | ----------------------------------- |
| Lever           | `jobs.lever.co/{company}`           |
| Greenhouse      | `boards.greenhouse.io/{company}`    |
| AshbyHQ         | `jobs.ashbyhq.com/{company}`        |
| Workable        | `apply.workable.com/{company}`      |
| Company careers | `{domain}/careers`, `{domain}/jobs` |

**What to extract:** Required technologies → confirmed in-use; vendor names (Workday, Salesforce, Snowflake) → SaaS tenants; compliance frameworks (SOC2, FedRAMP, HIPAA, PCI) → defensive priorities; cloud + on-prem ratio hints.

---

## Sat Imagery for Physical Recon

| Source                      | URL                             | Notes                                              |
| --------------------------- | ------------------------------- | -------------------------------------------------- |
| **Google Earth Pro**        | desktop app                     | Historical timeline; sub-meter for major cities    |
| **Google Maps**             | maps.google.com                 | Street view inside building lobbies sometimes      |
| **Bing Maps Bird's Eye**    | bing.com/maps                   | Oblique 45-degree; shows facades better            |
| **NearMap** (paid)          | nearmap.com                     | Highest-resolution; frequent updates (US/AU/NZ/CA) |
| **Sentinel Hub EO Browser** | apps.sentinel-hub.com           | Free Sentinel-2 (10m); change detection            |
| **Wayback ArcGIS**          | livingatlas.arcgis.com/wayback/ | Historical satellite                               |

**What to extract:** entrance count/locations, parking lot ingress, fence lines, HVAC/utility access, adjacent occupants, smoking area locations (social-engineering staging), vehicle types.

**OSINT beyond satellites:** LinkedIn employee photos (badge templates visible), Glassdoor office tour photos, Instagram geotagged photos at office address, press release "ribbon cutting" photos.

### Vehicle / Fleet Intel

- License plates in LinkedIn/Instagram backgrounds — sometimes correlates to specific exec.
- Company-branded vehicles in sat imagery — fleet count + location.
- Helicopter pad / executive parking — clue to senior-leadership routine.

### Physical Recon Discipline

- Document that imagery + photos are public-source.
- Don't trespass for "verification" — physical recon during OSINT phase = look only.
- Note imagery date — buildings change.

---

## General OSINT References

- [OSINT Framework](https://osintframework.com/) — categorized tree of OSINT tools.
- [IntelTechniques](https://inteltechniques.com/tools/) — Bazzell's tool collection.
- [Bellingcat Online Investigations Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) — investigative toolkit.
- [CyberSudo OSINT Lists](https://github.com/CyberSudo) — curated lists.
- [DDoSecrets](https://ddosecrets.com/) — leaked dataset reference.
- [DigitalDigging](https://digitaldigging.org/) — OSINT training resources.

---

## Search Engines

| Tool         | URL                   | Notes                          |
| ------------ | --------------------- | ------------------------------ |
| Carrot2      | carrot2.org           | Clustering search results      |
| etools       | etools.ch             | Metasearch                     |
| Kagi         | kagi.com              | Premium; programmable lenses   |
| Brave Search | search.brave.com      | Independent index; AI answer   |
| PDF Search   | pdf-search-engine.com | Specifically for PDF documents |

---

## Infrastructure & Attack-Surface OSINT

| Tool                                                  | URL                | Notes                             |
| ----------------------------------------------------- | ------------------ | --------------------------------- |
| [Shodan](https://www.shodan.io/)                      | shodan.io          | Banner search, InternetDB         |
| [Censys](https://search.censys.io/)                   | censys.io          | Certificate + host search         |
| [GreyNoise](https://www.greynoise.io/)                | greynoise.io       | Internet background noise         |
| [SecurityTrails](https://securitytrails.com/)         | securitytrails.com | DNS history + IP WHOIS            |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | GitHub             | Open-source OSINT automation      |
| [BuiltWith](https://builtwith.com/)                   | builtwith.com      | Technology profiling              |
| [Netlas](https://netlas.io/)                          | netlas.io          | Attack surface search             |
| [BinaryEdge](https://www.binaryedge.io/)              | binaryedge.io      | Internet scan                     |
| [ZoomEye](https://www.zoomeye.org/)                   | zoomeye.org        | Chinese search engine for devices |
| [Wappalyzer](https://www.wappalyzer.com/)             | wappalyzer.com     | Web technology fingerprinting     |
| [Hurricane Electric BGP Toolkit](https://bgp.he.net/) | bgp.he.net         | ASN/BGP lookup                    |
| [PeeringDB](https://www.peeringdb.com/)               | peeringdb.com      | Peering/IX data                   |

---

## WHOIS Historical & Reverse Lookup

| Source                                        | Notes                                              |
| --------------------------------------------- | -------------------------------------------------- |
| [DomainTools](https://www.domaintools.com/)   | Gold-standard for historical WHOIS + reverse WHOIS |
| [SecurityTrails](https://securitytrails.com/) | Free historical DNS; limited historical WHOIS      |
| [viewdns.info](https://viewdns.info/)         | Basic reverse WHOIS                                |

**Reverse-WHOIS example (DomainTools API):**

```text
https://reverse-whois-api.domaintools.com/v1?terms={"registrant_org":"Acme%20Corp"}&mode=purchase
```

---

## Geospatial Intelligence

### Satellite & Mapping

- Google Maps / Google Earth Pro (historical timeline, sub-meter for major cities).
- Bing Maps Bird's Eye (oblique 45-degree views).
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/) — Free Sentinel-2 (10m); change detection.
- [NASA Worldview](https://worldview.earthdata.nasa.gov/) — near-real-time satellite.
- [Wayback ArcGIS](https://livingatlas.arcgis.com/wayback/) — historical satellite.
- [Zoom Earth](https://zoom.earth/) — near-real-time weather + satellite imagery.
- [Open Infrastructure Map](https://openinframap.org/) — global power/telecom/pipeline infrastructure overlay.
- [Maxar](https://www.maxar.com/) / [Planet Labs](https://www.planet.com/) — commercial high-res imagery (paid).

### Geolocation Tools

- [Mapillary](https://www.mapillary.com/) — crowd-sourced street imagery.
- [KartaView](https://kartaview.org/) — open street imagery.
- [Overpass Turbo](https://overpass-turbo.eu/) — OpenStreetMap query engine.
- [SunCalc](https://www.suncalc.org/) — shadow analysis for chronolocation.

### Flight OSINT

- [FlightRadar24](https://www.flightradar24.com/), [ADSBExchange](https://globe.adsbexchange.com/) — unfiltered.
- [FlightAware](https://www.flightaware.com/) — flight tracking + historical data.
- [Planespotters](https://www.planespotters.net/) — fleet/airframe history.
- [AirFrames](https://www.airframes.org/), [JetPhotos](https://www.jetphotos.com/) — aircraft photo databases.

### Maritime OSINT

- [MarineTraffic](https://www.marinetraffic.com/), [VesselFinder](https://www.vesselfinder.com/), [Global Fishing Watch](https://globalfishingwatch.org/).

---

## Regional Search Engines

### Russia / CIS

- Yandex (yandex.ru), Mail.ru, VK (vk.com), OK.ru (Odnoklassniki).

### China

- Baidu (baidu.com), Sogou (sogou.com), 360 Search (so.com), Weibo (weibo.com), Zhihu (zhihu.com).
- [Douyin](https://www.douyin.com/) — Chinese TikTok (short video platform).

---

## Public Records & Company Information

### General

- [OpenCorporates](https://opencorporates.com/) — global company registry search.
- [SEC EDGAR](https://www.sec.gov/cgi-bin/browse-edgar) — US public company filings.
- [OpenOwnership](https://register.openownership.org/) — beneficial ownership.
- [MuckRock](https://www.muckrock.com/) — FOIA request platform.
- [UK Companies House](https://find-and-update.company-information.service.gov.uk/) — UK company registry.

### Russia

- [Rusprofile](https://www.rusprofile.ru/) — company + director search.
- [Kontur.Focus](https://focus.kontur.ru/) — Russian company analytics.
- [zakupki.gov.ru](https://zakupki.gov.ru/) — Russian procurement.

### China

- [GSXT](https://www.gsxt.gov.cn/) — national enterprise credit system.
- [USCC](https://www.uscc.gov/) — US-China Economic and Security Review Commission.
- ICP Beian (beian.miit.gov.cn) — domain registration records.

### Sanctions & Compliance

- [OFAC](https://sanctionssearch.ofac.treas.gov/) — US sanctions list.
- [OpenSanctions](https://www.opensanctions.org/) — aggregated sanctions data.
- [OCCRP Aleph](https://aleph.occrp.org/) — investigative data.

---

## LinkedIn Employee Enumeration Tools

- [theHarvester](https://github.com/laramies/theHarvester) — email + subdomain harvester.
- [CrossLinked](https://github.com/m8sec/CrossLinked) — LinkedIn scraper → employee list.

---

## Video Analysis

- [YouTube Data Viewer](https://citizenevidence.amnestyusa.org/) (Amnesty International), [InVID & WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [YouTube Geo Tag](https://mattw.io/youtube-geofind/location), [MediaInfo](https://mediaarea.net/en/MediaInfo), Snap Map.

---

## Image Forensics & Metadata

- [Jimpl](https://jimpl.com/), [Jeffrey's EXIF Viewer](http://exif.regex.info/exif.cgi), [FOCA](https://www.elevenpaths.com/labstools/foca), [Metagoofil](https://www.edge-security.com/metagoofil.php), [C2PA Verify](https://verify.contentauthenticity.org/).

---

## Browser Extensions for Media OSINT

- [Fake News Debunker (InVID & WeVerify)](https://chrome.google.com/webstore/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe)
- [RevEye Reverse Image Search](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/kejaocbebojdmebagkjghljkeefgimdj)
- [EXIF Viewer Pro](https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm)
- [Wayback Machine Extension](https://chrome.google.com/webstore/detail/wayback-machine/fpnmgdkabkmnadcjpehmlllkndpkmiak)
- [Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci)

---

## Commercial AI OSINT Platforms

- [Cylect](https://www.cylect.io/) — entity extraction + link analysis.
- [Fivecast Matrix](https://www.fivecast.com/products/matrix/) — generative-AI triage for social-media datasets.
- [Recorded Future](https://www.recordedfuture.com/) — AI-driven threat intel.
- [DarkOwl Vision](https://www.darkowl.com/) — darknet data analysis.

---

## Deepfake & Synthetic Media Detection

- [Sensity AI](https://sensity.ai/), [Reality Defender](https://realitydefender.com/), [Adobe Content Credentials Verify](https://contentcredentials.org/verify), [CarNet](https://carnet.ai/).

---

## Automation & Workflow Tools

- [n8n](https://n8n.io/) — self-hosted workflow automation (RSS → scrape → alert pipelines).
- [Huginn](https://github.com/huginn/huginn) — agent-based monitoring/scraping/alerting.
- [Playwright](https://playwright.dev/) — headless browser automation with stealth plugins.
- [Browsertrix Crawler](https://github.com/webrecorder/browsertrix-crawler) — archival crawling with WARC export.
- [Prefect](https://www.prefect.io/) / [Apache Airflow](https://airflow.apache.org/) — workflow orchestration.

---
