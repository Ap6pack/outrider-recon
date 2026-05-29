# Specialty OSINT Domains

> Encyclopedic reference for domain-specific OSINT techniques.
> Extracted from skill files for clean separation.

---

## Specialty OSINT Techniques

**Cryptocurrency** — track flows with Cielo, TRM, Arkham, MetaSleuth. L2/rollup: start at L1 bridge events; use L2 explorers for in-rollup activity. Caution: bridges mint/burn (avoid 1:1 flow assumptions); MEV paths create false direct trails.

**Image / Video / Chronolocation** — reverse image search (Google Lens, Yandex, TinEye); EXIF via ExifTool; forensics via Forensically/FotoForensics; geolocation via foreground+background landmark analysis, Street View, Overpass Turbo, PeakVisor. Shadow analysis: SunCalc, ShadeMap. Satellite: Google Earth Pro historical, Sentinel Hub.

**Threat Actor Investigation** — scoping: actor hypothesis from CERT/vendor reports → IOC harvest → infra mapping via CT log pivots, shared hosting, NS reuse, HTML fingerprints → artifact profiling (PDB paths, Rich headers, SSDEEP/YARA) → social pivots (handles, code snippets, job posts). Attribution discipline: rule of three; separate capability from intent; prefer durable pivots (code-signing certs, build path idioms) over ephemeral (resolving IPs). Russia pivots: EGRUL, Rusprofile, hh.ru, VKontakte. China pivots: gsxt.gov.cn, Tianyancha, ICP filings, Weibo, Zhihu.

**People & Social Media** — username enumeration: WhatsMyName, Sherlock, Maigret. Face search: PimEyes, Exposing.ai. Social graph: Maltego, SocialBlade. Bluesky: DID resolution via `bsky.social/xrpc/`, firehose via Firesky. Mastodon: WebFinger discovery; FediSearch cross-instance.

---

## Sector-Specific Recon Notes

### Healthcare
- **DICOM** (medical imaging) — port 11112, sometimes 4242.
- **HL7 v2** — port 2575 (TCP, often plaintext). Legacy but still widespread; carries ADT, ORM, ORU messages with patient demographics in the clear.
- **HL7 FHIR** — `/fhir/R4/<resource>` paths; OAuth / SMART-on-FHIR posture varies widely.
- **PACS/RIS/EHR vendors:** Epic (`*.epic.com`), Cerner/Oracle Health, Allscripts/Veradigm, Athenahealth, NextGen, Meditech, eClinicalWorks.
- **Searches:** `site:{domain} ("EHR" OR "PACS" OR "PHI" OR "HIPAA")`, `intitle:"Epic Systems" "{target}"`.
- **Severity:** any PHI exposure → **CRITICAL**; HL7/DICOM open without auth → **CRITICAL**.

#### HL7 v2 Message Structure Deep Dive

HL7 v2 messages are pipe-delimited and carry structured patient data. Key segments to look for during recon:

- **MSH** (Message Header) — contains sending/receiving application names, facility identifiers, message type (e.g., `ADT^A01` for admission), and processing IDs. The `MSH-3` and `MSH-4` fields reveal internal application names and facility codes that aid infrastructure mapping.
- **EVN** (Event Type) — timestamps of clinical events. Useful for confirming an active HL7 feed (recent timestamps = live system).
- **PID** (Patient Identification) — carries patient name, DOB, SSN, address, phone number, and MRN. If PID segments are visible in cleartext traffic on port 2575, this constitutes an immediate CRITICAL PHI exposure.
- **PV1** (Patient Visit) — attending physician, admission type, assigned location (ward/bed). Reveals organizational structure.
- **OBX** (Observation/Result) — lab values, vital signs. Confirms clinical data flowing through the interface.

Capture technique: passive TCP capture on port 2575; HL7 v2 is almost never TLS-wrapped in legacy environments. Even a brief packet capture may reveal dozens of patient records.

#### FHIR Endpoint Enumeration

FHIR (Fast Healthcare Interoperability Resources) R4 servers expose a discoverable API surface:

- **`/metadata`** — returns the server's `CapabilityStatement` (formerly `Conformance`). This reveals every supported resource type, search parameters, supported operations, and security extensions. Always enumerate this first.
- **`/Patient`** — patient demographics. Check if `_search` is enabled without OAuth. Even with auth, error messages may leak schema details.
- **`/Practitioner`** — provider directory. Often less protected than patient data; reveals physician names, NPIs, specialties.
- **`/Organization`** — organizational hierarchy. Maps departments, facilities, and affiliations.
- **`/Encounter`**, **`/Observation`**, **`/DiagnosticReport`** — clinical data endpoints. Attempt unauthenticated GET requests; many implementations default to open access during development and forget to lock down.
- **Bulk Data Export** — `/$export` endpoint (Bulk FHIR). If enabled without auth, can dump entire patient populations.

#### SMART-on-FHIR OAuth Discovery

SMART-on-FHIR uses a well-known discovery endpoint for OAuth configuration:

- Fetch `https://{fhir-server}/.well-known/smart-configuration` — returns JSON with `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, and supported scopes.
- Also check `https://{fhir-server}/metadata` for the `security` extension containing OAuth URIs.
- Look for `registration_endpoint` — if dynamic client registration is enabled, an attacker can register their own OAuth client.
- Scope enumeration: check for overly broad scopes like `patient/*.read` or `user/*.*`.

#### Common EHR Vendor URL Patterns

- **Epic:** `*.epic.com`, `mychart.{org-domain}.org`, `/interconnect-{env}/api/FHIR/R4/`, `/FHIRProxy/`, `/MyChart/Authentication/Login`
- **Cerner (Oracle Health):** `/fhir/r4/`, `cernerhealth.com`, `*.cerner.com`, `/HealtheLife/`
- **Allscripts/Veradigm:** `/Unity/UnityService.svc`, `/fhir/r4/`, `*.allscriptscloud.com`
- **Athenahealth:** `*.athenahealth.com`, `/fhir/r4/`, `/api/`, `/1/{practice-id}/`
- **NextGen:** `*.nextgen.com`, `/nge-api/`, `/fhir-api/`
- **Meditech:** `*.meditech.com`, `/ehr/`, `/MagicFS/`
- **eClinicalWorks:** `*.eclinicalworks.com`, `/mobiledoc/`, `/fhir/r4/`

#### PHI Leakage Dork Patterns

Targeted search dorks for identifying exposed PHI:

- `site:{domain} filetype:pdf "patient" "DOB"` — discharge summaries, lab reports accidentally published.
- `site:{domain} filetype:pdf "medical record number" OR "MRN"` — records with explicit MRN references.
- `site:{domain} filetype:xlsx "patient" "SSN"` — spreadsheets with demographics.
- `site:{domain} filetype:csv "diagnosis" "ICD"` — coding data exports.
- `site:{domain} inurl:"/fhir/" "Patient"` — exposed FHIR endpoints indexed by search engines.
- `site:{domain} intitle:"index of" "hl7" OR "adt" OR "orm"` — directory listings of HL7 message files.
- `site:{domain} "HIPAA" "breach" filetype:pdf` — breach notification documents revealing infrastructure details.

### Finance
- **SWIFT terminals** — internal-only; if external-facing → **CRITICAL**.
- **FIX protocol** (electronic trading) — port 9876; cleartext.
- **Bloomberg terminals** — typically VDI-delivered; check for `bloomberg.com`-related auth surfaces exposed on the target's perimeter.
- **Trading platform vendors:** Fidessa, Charles River, Eze Software, Aladdin (BlackRock).
- **Banking middleware:** Temenos T24, Finacle (Infosys), FIS, Jack Henry, Fiserv. Each has known CVE history; version-fingerprint when possible.
- **Searches:** `site:{domain} ("PCI" OR "SOX" OR "GLBA" OR "MAS")`, `intitle:"Temenos" "{target}"`.
- **Severity:** any account/balance data exposure → **CRITICAL**; SWIFT → **CRITICAL**; trade-execution surface → **CRITICAL**.

#### FIX Protocol Fingerprinting

FIX (Financial Information eXchange) protocol is the backbone of electronic trading. Recon techniques:

- **Logon message (MsgType=A):** the initial handshake reveals `SenderCompID` (tag 49), `TargetCompID` (tag 56), `HeartBtInt` (tag 108), and optionally `Username` (tag 553). These identify the firm, counterparty, and session configuration.
- **Session-level vs. application-level:** session messages (Logon, Heartbeat, Logout) establish connectivity. Application messages (NewOrderSingle=D, ExecutionReport=8, MarketDataRequest=V) carry business logic. Observing application-level traffic confirms a live trading connection.
- **Version fingerprinting:** the `BeginString` field (tag 8) reveals the FIX version: `FIX.4.0` through `FIX.4.4`, or `FIXT.1.1` for FIX 5.0+. Older versions lack security features.
- **Cleartext exposure:** FIX on port 9876 (or vendor-specific ports) is frequently unencrypted. A passive capture reveals order flow, position data, and counterparty identities.
- **Common vendor ports:** Bloomberg EMSX (various), Fidessa (9878), CQG (various), TT (Trading Technologies, 10400+).

#### PCI DSS 4.0 External Scan Requirements

Understanding what Approved Scanning Vendors (ASVs) look for helps frame findings:

- **Quarterly external vulnerability scans** are mandatory for all entities storing, processing, or transmitting cardholder data.
- ASVs check for: unpatched services, SSL/TLS misconfigurations (SSLv3, TLS 1.0/1.1, weak ciphers), default credentials, known CVEs with CVSS >= 4.0, exposed admin interfaces, directory traversal, SQL injection.
- **PCI DSS 4.0 additions:** requirement 6.4.1 mandates a web application firewall (WAF) for public-facing web apps; 11.3.1 requires internal vulnerability scans; 12.3.1 requires targeted risk analysis. Absence of WAF headers on payment pages is a reportable finding.
- **Scope inference:** identify cardholder data environment (CDE) boundaries by locating payment pages, tokenization services, and PCI-scoped IP ranges listed in the ASV scan attestation (sometimes publicly filed).

#### SWIFT Alliance Lite2 Web Interface

SWIFT Alliance Lite2 provides browser-based access to the SWIFT network for smaller institutions:

- **Default paths:** `/lite2/`, `/swiftalliance/`, `/alliance/`, `/sag/` (SWIFT Alliance Gateway).
- **Login page fingerprints:** page titles containing "SWIFT Alliance" or "Alliance Lite2"; specific CSS/JS asset paths unique to the platform.
- **If externally reachable:** immediate CRITICAL. SWIFT interfaces must never face the internet. Even a login page confirms the institution's SWIFT membership and suggests potential for SWIFT-level compromise (cf. Bangladesh Bank 2016).
- **Related infrastructure:** SWIFT Alliance Access (on-premises), Alliance Connect (VPN-based). Look for VPN concentrators with SWIFT-associated naming conventions.

#### Banking API Surface

Modern banking exposes significant API attack surface through open banking mandates:

- **Open Banking (UK):** regulated by OBIE. Endpoints at `https://{bank}/open-banking/v3.1/`. Resource types: `/accounts`, `/balances`, `/transactions`, `/beneficiaries`. Discovery via Open Banking Directory (directory.openbanking.org.uk).
- **PSD2 (EU):** mandates payment initiation (PISP) and account information (AISP) APIs. Berlin Group NextGenPSD2 standard: `/v1/accounts`, `/v1/payments`. Discovery via national registries (e.g., FCA register for UK TPPs).
- **Plaid endpoints:** `/link/token/create`, `/transactions/get`, `/auth/get`. Look for exposed Plaid `client_id` values in JavaScript bundles or mobile app decompilation.
- **Yodlee/Envestnet:** `/v1/user`, `/v1/accounts`. Legacy integrations sometimes use Basic auth with hardcoded credentials in mobile apps.
- **MX platform:** `/users/{user_guid}/members`, `/institutions`. Check for exposed API keys in front-end code.

#### Crypto Exchange Recon

Cryptocurrency exchanges present unique reconnaissance opportunities:

- **API documentation:** most exchanges publish REST and WebSocket API docs. These reveal rate limits, authentication mechanisms, available endpoints, and sometimes internal infrastructure details in example responses.
- **Withdrawal address patterns:** monitor on-chain for known hot wallet addresses (published in proof-of-reserves or discoverable via large-volume transaction clustering). Tools: Arkham, Nansen, Chainalysis.
- **Custody provider inference:** regulatory filings (e.g., SEC, FCA) often name custodians (Fireblocks, BitGo, Copper, Anchorage). This reveals additional attack surface through the custodian's infrastructure.
- **Order book / WebSocket endpoints:** `wss://{exchange}/ws`, `/api/v1/depth`, `/api/v1/ticker`. Even authenticated endpoints sometimes leak data in error responses.
- **Common exchange tech stacks:** matching engine vendors (e.g., LMAX, proprietary), cloud providers (infer from IP ranges, CDN headers), WAF vendors (from response headers).

### ICS / SCADA / OT

> **Caution:** even passive scanning can disrupt ICS. Do NOT actively probe without explicit RoE + OT team coordination.

- **Modbus** — port 502 (TCP). **BACnet** — port 47808 (UDP). **Siemens S7** — port 102.
- **DNP3** — port 20000 (TCP).
- **EtherNet/IP** — port 44818 (TCP).
- **Niagara Framework** — ports 1911, 4911, 5011, 502.
- **Honeywell EBI / Tridium** — port assignments vary by deployment.
- **GE Proficy / iFIX** — port assignments vary by deployment.
- **Common findings:** unauthenticated read access (BACnet point list, Modbus register read), default creds on HMI panels, public-facing engineering workstations.
- **Detectability:** medium-to-high; ICS networks often have low background traffic and are heavily monitored.
- Sources: Shodan ICS-specific filters (`port:502`, `tag:ics`), Censys, Onyphe.

#### Shodan Dorks for ICS Discovery

Targeted Shodan queries for identifying internet-exposed ICS devices:

- **Modbus:** `"port:502"` — returns Modbus TCP devices. Refine with `"Schneider Electric"`, `"Siemens"`, or `"Modicon"` for vendor-specific results.
- **BACnet:** `"port:47808"` — Building Automation and Control networks. Add `"BACnet"` to filter for confirmed BACnet devices. Returns object names, device descriptions, and firmware versions.
- **Siemens S7:** `"port:102"` — S7comm protocol. Refine: `"module"` to see PLC module info, or `"Siemens" "port:102"` for confirmed Siemens PLCs. Returns module type, serial number, plant identification.
- **DNP3:** `"port:20000"` — Distributed Network Protocol. Common in electric utilities and water systems.
- **EtherNet/IP:** `"port:44818"` — CIP (Common Industrial Protocol) over Ethernet. Returns vendor name, product name, serial number, device type.
- **Niagara Fox:** `"port:1911" "Fox"` — Tridium Niagara Framework. Returns station name, application name, VM details, OS info.
- **Combined:** `tag:ics country:US` — all ICS-tagged devices in a given country. Cross-reference with target's known facility locations.

#### ICS Protocol Fingerprinting Commands

Tools for active fingerprinting (use ONLY with explicit OT team authorization):

- **modbus-cli:** `modbus read {ip} 0 10` — reads 10 holding registers starting at address 0. Reveals register contents and confirms Modbus connectivity. Use `--slave {unit-id}` for multi-drop configurations.
- **nmap ICS scripts:** `nmap --script modbus-discover -p 502 {ip}` — enumerates Modbus device ID. `nmap --script bacnet-info -p 47808 {ip}` — retrieves BACnet device info including vendor, model, firmware. `nmap --script s7-info -p 102 {ip}` — extracts S7 PLC details (module type, serial, plant ID).
- **bacnet-scan / BACpypes:** `bacnet-scan --range {ip-range}` — discovers BACnet devices on a network segment. Returns device instance, object name, vendor name, model, firmware version.
- **plcscan:** `python plcscan.py {ip}` — multi-protocol ICS scanner supporting Modbus, S7, and BACnet. Returns device identification and basic configuration.
- **cotp-tsap-brute:** brute-forces S7 TSAP (Transport Service Access Point) values to identify accessible S7 connection slots.

#### SCADA HMI Vendor Patterns

Web-based HMI (Human-Machine Interface) panels are frequently internet-exposed:

- **Wonderware (AVEVA InTouch):** URL patterns include `/InTouch/`, `/ArchestrA/`, `/SuiteLink/`. Login pages reference "Wonderware" or "AVEVA" in page titles. Default port 80/443 with IIS backend.
- **Ignition (Inductive Automation):** default port 8088 (HTTP) or 8043 (HTTPS). Path: `/main/web/login`, `/data/`. Gateway status page at `/StatusPing`. Page title: "Ignition Gateway". Extremely common in water/wastewater and manufacturing.
- **FactoryTalk (Rockwell Automation):** paths include `/FactoryTalk/`, `/RSView/`, `/FTView/`. Often paired with port 44818 (EtherNet/IP). FactoryTalk ViewPoint exposes HMI via browser at `/ViewPoint/`.
- **WinCC (Siemens):** paths include `/WinCC/`, `/WebNavigator/`. WinCC WebNavigator provides remote HMI access; default port 80/443. Look for page titles containing "SIMATIC WinCC".
- **GE iFIX / CIMPLICITY:** paths include `/ifix/`, `/cimplicity/`. WebSpace component exposes HMI graphics via browser.
- **Shared indicators:** HMI panels often display process diagrams, tank levels, valve states, or SCADA schematics on login pages themselves — even without authentication, the login page may reveal operational details.

#### OT-Specific Operational Caution

ICS/OT environments demand a fundamentally different approach to recon:

- **Passive only by default.** Active scanning (even SYN scans) can crash PLCs, trip safety interlocking systems, or cause physical process disruptions. A crashed PLC in a chemical plant or power grid is a safety-of-life event.
- **Explicit OT team coordination required.** Never scan ICS networks without written authorization from the OT/ICS team, not just the IT security team. OT teams maintain change windows and understand which devices tolerate scanning.
- **Prefer Shodan/Censys passive data.** Use internet scan databases to identify exposed ICS devices without sending any packets to the target. Historical Shodan data can show when devices appeared or disappeared.
- **Network segmentation validation.** A key finding is whether ICS devices are reachable from the corporate network or internet at all. If reachable, that alone is a CRITICAL finding regardless of vulnerability state.
- **ICS-CERT advisories.** Cross-reference discovered device models against CISA ICS-CERT advisories (cisa.gov/uscert/ics) for known vulnerabilities. Report CVEs without testing exploits in OT environments.

### IoT / Consumer / SOHO
- **MQTT** — port 1883 (cleartext), 8883 (TLS). Topics often readable without auth.
- **CoAP** — port 5683 (UDP). Lightweight IoT protocol; may expose device resources without authentication.
- **UPnP / SSDP** — port 1900 (UDP); often discloses internal device map and service endpoints.
- **Common router admin patterns:** `/cgi-bin/`, `/setup.cgi`, `/admin/index.html`. Default creds are the norm.
- **Camera DVRs/NVRs** — Hikvision, Dahua, Axis. Multiple CVEs; frequently internet-facing with factory defaults.
- **Smart-home hubs** — exposed APIs sometimes leak auth tokens or device inventories.

#### Default Credential Databases

IoT devices ship with well-documented default credentials. Recon resources:

- **defaultpassword.com** — searchable database indexed by vendor and model. Cross-reference discovered device models during enumeration.
- **cirt.net/passwords** — comprehensive default password list organized by manufacturer. Includes routers, switches, cameras, printers, and industrial devices.
- **Mirai source code wordlists** — the Mirai botnet source (widely published) contains the credential pairs used against IoT devices in the wild. These represent the most commonly successful defaults.
- **Vendor documentation** — many vendors publish default credentials in publicly available installation guides (searchable via `site:{vendor} "default password" filetype:pdf`).
- **Operational note:** during authorized testing, attempt default credentials only after confirming scope and rules of engagement. Document each attempt. Default credential access on IoT is almost always successful and constitutes a valid finding.

#### Firmware Extraction and Analysis

Extracting and analyzing firmware reveals hardcoded credentials, API keys, and internal architecture:

- **binwalk:** `binwalk -e firmware.bin` — extracts embedded filesystems, compressed archives, and executable code from firmware images. Use `binwalk -Me` for recursive extraction. Look for `/etc/shadow`, `/etc/passwd`, hardcoded API keys, SSL private keys, and configuration files.
- **jefferson:** `jefferson firmware.jffs2 -d output/` — extracts JFFS2 filesystems (common in embedded Linux devices). JFFS2 is used by many routers and IoT devices.
- **ubi_reader:** `ubireader_extract_images firmware.ubi` — extracts UBI/UBIFS filesystems (common in modern embedded devices using NAND flash).
- **Firmware acquisition:** download from vendor support pages, intercept OTA update traffic (check for HTTP update URLs in device traffic), or extract directly from flash chips via SPI/JTAG interfaces.
- **Post-extraction analysis:** `grep -r "password\|secret\|key\|token" extracted_fs/` for hardcoded secrets. Run `strings` on binaries for URLs, IP addresses, and debug messages. Check for telnet/SSH backdoors on non-standard ports.

#### UPnP/SSDP Discovery

Universal Plug and Play exposes device information and control interfaces:

- **gssdp-discover:** `gssdp-discover --timeout=5` — sends M-SEARCH requests and collects SSDP responses from the local network. Returns device types, service descriptions, and location URLs for XML device descriptors.
- **miranda:** `miranda.py` — interactive UPnP exploration tool. Commands: `msearch` (discover devices), `host list` (show discovered devices), `host info {n}` (detailed device info), `host send {n} {service} {action}` (invoke UPnP actions). Can enumerate WANIPConnection for port mapping, retrieve external IP, and potentially add port forwarding rules.
- **What UPnP reveals:** device manufacturer, model name, model number, serial number, firmware version, and all exposed services (e.g., WANIPConnection, WANPPPConnection, AVTransport). The XML device descriptor at the advertised `LOCATION` URL is a goldmine for fingerprinting.
- **Attack surface:** UPnP IGD (Internet Gateway Device) allows unauthenticated port forwarding manipulation. Check if `AddPortMapping` is accessible — this can be used to expose internal services through the router.

#### Camera/DVR Vendor Fingerprints

IP cameras and DVRs are among the most commonly exposed IoT devices:

- **Hikvision:** paths `/ISAPI/`, `/System/deviceInfo`, `/PSIA/System/deviceInfo`. Login page at `/doc/page/login.asp`. Default creds: `admin/12345` (older) or `admin/{activation-password}`. Page title often contains "Hikvision" or "DNVRS-Webs". Known CVEs: CVE-2021-36260 (command injection, no auth required).
- **Dahua:** paths `/cgi-bin/configManager.cgi`, `/RPC2`, `/current_config/`. Login page at `/`. Default creds: `admin/admin`. HTTP response headers may contain `DH-` prefixed custom headers. Known CVEs: CVE-2021-36260 (auth bypass via crafted header).
- **Axis:** paths `/axis-cgi/`, `/view/viewer_index.shtml`, `/mjpg/video.mjpg`. VAPIX API at `/axis-cgi/param.cgi`. Page title: "AXIS" or "Live View". Generally better security posture than consumer brands but still frequently found with defaults.
- **Generic DVR/NVR:** look for `XMEye`, `CMS`, `NetSurveillance` in page titles — these indicate white-label Chinese DVRs (XiongMai/HiSilicon SoC) with well-known backdoors and default passwords (`admin/` with empty password, or `admin/xmhdipc`).

### Government
- **FedRAMP / FISMA / DoD CMMC** — defensive posture generally above baseline.
- `.gov` and `.mil` domains require special engagement-scope discipline; verify authorization explicitly before any active interaction.
- **OSINT data sources:** USAspending.gov, SAM.gov (System for Award Management), FBO.gov / sam.gov (procurement).
- **Common findings:** vendor of record disclosed in public contracts → adjacent-vendor pivot for supply-chain attack surface.
- Severity: as high or higher than commercial; political sensitivity on top.

#### SAM.gov Contract Mining for Tech Stack Inference

The System for Award Management (SAM.gov) is a public database of federal contracts that reveals technology choices:

- **Search by agency or contractor:** `sam.gov/search/?keywords={target-agency}` — returns awarded contracts with descriptions, dollar amounts, NAICS codes, and contractor details.
- **What contracts reveal:** product names (e.g., "Palo Alto Networks" firewall deployment), cloud providers (e.g., AWS GovCloud migration), system integrator relationships (e.g., Booz Allen, Leidos, SAIC), and software platforms (e.g., ServiceNow, Splunk, CrowdStrike).
- **NAICS code filtering:** 541512 (Computer Systems Design), 541519 (Other Computer Related Services), 518210 (Cloud Computing/Data Processing). These codes isolate technology-related contracts.
- **USAspending.gov** — provides additional spending details, sub-awards, and historical trends. Useful for identifying when contracts expire (potential transition windows = higher attack surface).
- **FPDS (Federal Procurement Data System):** fpds.gov provides granular contract data including modifications, options exercised, and performance periods.

#### FedRAMP Marketplace for Cloud Service Identification

FedRAMP authorization records reveal which cloud services government agencies use:

- **FedRAMP Marketplace:** `marketplace.fedramp.gov` — searchable database of FedRAMP-authorized cloud services. Filter by sponsoring agency to see which cloud products a specific agency has authorized.
- **What it reveals:** cloud provider (AWS, Azure, GCP, Oracle Cloud), SaaS platforms (Salesforce Government Cloud, ServiceNow Federal, Microsoft 365 GCC/GCC-High), and security authorization levels (Low, Moderate, High, DoD IL2-IL6).
- **Authorization packages:** FedRAMP authorization documents (SSP, SAR, POA&M) are not public, but the fact of authorization and the authorization boundary description often are. This reveals network architecture at a high level.
- **Agency ATO (Authority to Operate) letters** — sometimes published or discoverable via FOIA. These confirm specific systems in production.

#### .gov/.mil Subdomain Patterns and Vendor Surfaces

Government domains follow predictable patterns that aid subdomain enumeration:

- **Common .gov subdomain patterns:** `mail.{agency}.gov`, `vpn.{agency}.gov`, `owa.{agency}.gov`, `citrix.{agency}.gov`, `remote.{agency}.gov`, `portal.{agency}.gov`, `apps.{agency}.gov`, `sso.{agency}.gov`.
- **Vendor-specific surfaces:** `{agency}-paloalto.gov` or `fw.{agency}.gov` (firewalls), `splunk.{agency}.gov` (SIEM), `servicenow.{agency}.gov` or `{agency}.service-now.com` (ITSM), `{agency}.sharepoint-mil.us` (DoD SharePoint).
- **Cloud-hosted patterns:** `{agency}.gov` CNAMEs pointing to `*.cloudfront.net`, `*.azurewebsites.net`, `*.amazonaws.com` — reveals cloud hosting. Dangling DNS (CNAME to deprovisioned cloud resource) enables subdomain takeover.
- **Certificate Transparency logs** — particularly valuable for .gov; use `crt.sh` with `%.{agency}.gov` to enumerate subdomains including internal-facing systems that obtained public certificates.
- **GSA common services:** login.gov (identity), cloud.gov (PaaS), federalist.18f.gov (static site hosting). If a target uses these, the underlying infrastructure is GSA-managed.

#### FISMA/FedRAMP Authorization Boundary Implications

Understanding authorization boundaries is critical for government engagement scoping:

- **FISMA authorization boundary** — defines the set of systems covered by a single ATO. Systems outside the boundary are out-of-scope for that authorization. During recon, identifying where the boundary lies reveals which systems are under centralized security management and which may be less monitored.
- **Interconnection Security Agreements (ISAs)** — govern connections between different authorization boundaries. The existence of ISAs (sometimes referenced in public documents) reveals system interconnections and data flows.
- **Cloud shared responsibility:** in FedRAMP environments, the CSP manages infrastructure security up to a defined layer; the agency manages everything above it. Misunderstandings at this boundary are a common source of misconfigurations.
- **Continuous monitoring (ConMon):** FedRAMP requires ongoing vulnerability scanning (monthly OS, annual pen test). Scan results feed into agency dashboards (e.g., DHS CDM program). Active scanning during recon may trigger CDM alerts and SOC response faster than in commercial environments.

### Maritime / Aviation / Automotive
- **Maritime:** AIS (Automatic Identification System) broadcasts vessel positions; tools: MarineTraffic, VesselFinder. Engine telemetry sometimes exposed via VSAT terminals.
- **Aviation:** ADS-B (Automatic Dependent Surveillance-Broadcast) — see flight OSINT tools (FlightRadar24, ADS-B Exchange). Operator/airline-specific OPS data sometimes exposed on misconfigured portals.
- **Automotive:** OEM telematics backends (Tesla, GM OnStar, etc.) — typically authenticated, but APIs leak via mobile-app reverse engineering. Connected-vehicle platforms may expose VIN-linked telemetry or remote-command endpoints.

---

### Universal Sector Caveat

> Most external recon techniques apply universally. Sector-specific protocols add attack surface; sector-specific compliance regimes add reporting requirements. Don't assume "healthcare/finance/etc. has different OSINT" — the OSINT is the same; the targeted services differ.

---

