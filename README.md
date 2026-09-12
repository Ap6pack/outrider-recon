![outrider-recon banner](assets/outrider-recon-banner.svg)

# outrider-recon

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude_Code-plugin-8A05FF.svg)](#quick-start)
[![MCP Server](https://img.shields.io/badge/MCP-enrichment-dc2626.svg)](mcp-server/)

> **Claude-native, governed offensive-OSINT and external attack-surface platform for authorized security teams.**

Outrider is the governed front half of the offensive workflow. It runs authorized, multi-agent OSINT and external attack-surface recon — across web and API, identity and SSO, cloud and infrastructure, secrets, and people/breach intelligence — under deterministic scope, evidence, and approval controls, then turns what it finds into prioritized, evidence-backed, human-reviewed findings to hand off to validation and pen-testing.

Outrider is intentionally not an exploitation framework. Active enumeration is approval-gated, intrusive validation is a human hand-off, and exploitation is out of scope by design.

---

## Table of contents

- [Overview](#overview)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Capabilities](#capabilities)
- [Example output](#example-output)
- [Installation](#installation)
- [Implementation status](#implementation-status)
- [Releases and versioning](#releases-and-versioning)
- [Current release candidates](#current-release-candidates)
- [Documentation](#documentation)
- [Project structure](#project-structure)
- [Authorization and security](#authorization-and-security)
- [About](#about)

---

## Overview

Most recon tooling tells you what exists: subdomains, ports, URLs, technologies, leaked files, and scanner output. Outrider focuses on the next question:

> **What matters first, and why?**

Use Outrider to:

- map an organization's authorized external attack surface;
- organize web/API, identity, cloud, SaaS, secrets, people, breach, and public-code signals;
- compare observations against public bug-bounty and attack-path patterns;
- rank leads by confidence, severity, detectability, and operator value;
- preserve local evidence and produce finding cards, technique cards, and report-ready notes;
- keep recon decisions inside deterministic scope, state, approval, and evidence controls.

Outrider fits between raw discovery tools and active testing:

```text
Outrider Recon → ranked leads / technique cards → proxy-assisted testing, manual validation, ASM tickets, or remediation
```

---

## Quick start

**Fastest path — one command.** From a checkout, `bootstrap.sh` creates an
isolated virtualenv, installs the package, links the Claude skills, and runs a
deterministic self-check so you know it works before touching a target:

```bash
git clone https://github.com/Ap6pack/outrider-recon.git
cd outrider-recon
./bootstrap.sh            # add --no-web for a base install, --no-skills to skip skill linking
source .venv/bin/activate
outrider                 # start the local browser portal
```

A healthy self-check ends with `promoted_findings_total: 0` and
`schema_validity_rate: 1.0`. That is the friction-free way to confirm the
install; no API keys, targets, or network needed.

**Just want to see it in a browser (Docker, Linux).** Outrider binds loopback
only by design, so share the host loopback with `--network host`:

```bash
docker build -t outrider-recon .
docker run --rm --network host outrider-recon
# then open http://127.0.0.1:8765
```

**Manual path.** Install the web extra and run `outrider`:

```bash
python -m pip install -e ".[web]"
outrider
```

The browser is the normal human interface. Use the guided wizard to create an authorized engagement, then choose **Review Scope**. CLI subcommands remain available for advanced automation and recovery. Discovery enrichment is disabled unless `outrider --enable-mcp-enrichment` is used.

This is the minimum successful path. For complete setup options, see [Installation](docs/installation.md) and [Usage](docs/usage.md).

### 1. Install the Claude skills

```bash
curl -fsSL https://raw.githubusercontent.com/Ap6pack/outrider-recon/main/install.sh | bash
```

This clones to `~/.local/share/outrider-recon` and symlinks all skills into `~/.claude/skills/`, so re-running it updates in place. For manual copies, Claude Desktop/API setups, and uninstall steps, see [Installation](docs/installation.md).

### 2. Install or download the Python CLI

From a source checkout:

```bash
git clone https://github.com/Ap6pack/outrider-recon.git
cd outrider-recon
python -m pip install -e .
```

For release artifacts and checksum verification, see [Release documentation](docs/releases/README.md).

### 3. Initialize a run

```bash
outrider init example.com \
  --actor authorized-operator \
  --authorization-reference EXAMPLE-ROE-001
```

### 4. Perform one scope check

```bash
outrider scope-check runs/example.com api.example.com
```

### 5. Continue with detailed usage

Use [docs/usage.md](docs/usage.md) for command workflows, Claude prompts, state transitions, evidence handling, approvals, contracts, finding promotion, reporting, and operational patterns.

---

## How it works

```text
Scope → Recon → Enrich → Score → Finding Cards → Handoff → Report
```

- **Claude skills** provide methodology, routing, operator checklists, scoring guidance, and report structure.
- **Python controls** provide deterministic local enforcement for run identity, workflow state, scope checks, approval policy, evidence integrity, contract validation, and finding promotion.
- **Optional MCP tools** provide policy-gated live enrichment for bounded public-source lookups and DNS records.
- **Optional web control plane** provides a local browser interface for creating guarded runs, reviewing run folders, replacing initialized scope rules, checking scope candidates, applying guarded workflow-state transitions, granting/revoking bounded approvals, checking action policy, inventorying artifact metadata, registering existing artifacts as evidence, and verifying evidence integrity; see [web review/control details](docs/web-review-plane.md).

The design keeps reasoning and enrichment separate from durable authorization, scope, evidence, and finding records. See [Architecture](docs/architecture.md), [Contracts](contracts/README.md), and the ADRs under [docs/adr/](docs/adr/) for details.

---

## Capabilities

**Recon & OSINT domains** — Claude skills spanning the external attack surface:

- external asset discovery and surface mapping (subdomains, DNS, certificates, WHOIS);
- web and API surface (OpenAPI/GraphQL, endpoints, security headers, JavaScript, email security, vendor/product fingerprints, cloud buckets);
- identity fabric — SSO/IdP fingerprinting, Microsoft 365 deep enumeration, and employee enumeration;
- cloud and infrastructure (cloud-native services, Kubernetes/containers, CI/CD, TLS);
- secrets and dorking, with read-only credential validation;
- people and breach intelligence (infostealer/breach correlation, package-registry leaks);
- post-credential enumeration (gated, read-only) for validated keys;
- analysis, scoring, attack-path hints, and bug-bounty / client reporting.

**Governance & orchestration** — the controls that make the above safe to run:

- deterministic scope, workflow-state, evidence-integrity, and approval controls;
- a governed agent-to-agent orchestrator that runs the skills through those controls (self-healing, crash-safe, bounded);
- an independent advisory verifier, a deterministic benchmark harness, and human-only finding promotion;
- optional policy-gated MCP enrichment, plus a CLI and a loopback-only web control plane.

**Where this fits** — Outrider is the governed recon half of the offensive life-cycle (recon → validation → reporting). Active enumeration is approval-gated and intrusive validation is a human hand-off today; extending the governed loop toward agent-to-agent validation is on the roadmap.

See [Capabilities](docs/capabilities.md) for the capability breakdown by domain and [Coverage](docs/coverage.md) for coverage by engagement phase.

---

## Example output

A useful recon workflow should not end with a flat list of hosts. Outrider aims to produce ranked, evidence-backed leads like this:

```text
[HIGH] api.acme.example exposes OpenAPI schema
Confidence: Confirmed
Evidence: GET /openapi.json returned 200; schema includes user/account/order paths
Why it matters: API schema reveals object identifiers and hidden write endpoints
Public report intelligence: similar disclosed reports map to IDOR, mass assignment, and broken authorization patterns
Recommended handoff: hunt-api-misconfig, hunt-idor, Burp Repeater authorization testing
Safe next step: verify auth requirements and object-level authorization without modifying production data
```

See [examples/05-sample-output.md](examples/05-sample-output.md) for a fuller sanitized example.

---

## Installation

Outrider has separate install paths for Claude skills, the Python CLI, optional web extras, and optional MCP server dependencies. The base Python package installs deterministic local controls and the CLI; web control-plane dependencies are installed with the `web` extra; MCP dependencies are installed from `mcp-server/requirements.txt` in a source checkout.

Use [docs/installation.md](docs/installation.md) for supported install patterns, including one-click install, manual Claude Code setup, editable Python installs, web extras, MCP setup, updates, and uninstall steps.

---

## Implementation status

Outrider currently has four implementation domains:

- **Claude skill layer:** implemented and used as the primary operator-facing capability layer.
- **Python CLI controls:** implemented for run scaffolding, local scope/state/evidence/approval/contract/finding checks, and guarded local review and control support.
- **Optional MCP enrichment:** implemented for bounded, policy-gated enrichment tools that require explicit run context before network or DNS activity.
- **Local web control plane:** implemented as a loopback-only control interface with guarded run creation, initialized-only scope replacement, browser scope checks, guarded workflow-state transitions, guarded approval grant/revocation, action-policy checks, metadata-only artifact inventory, existing-artifact evidence registration, evidence-integrity verification, guarded skill request creation, and request/result contract validation; artifact transfer, evidence editing/deletion, result creation/upload, automatic finding promotion, finding editing/deletion, result upload, skill execution, report generation, exports, arbitrary MCP servers, and recon remain unsupported in the browser. Explicit human finding promotion and explicitly enabled fixed MCP invocation are supported.

The repository does not claim to execute full automated recon on its own. It is a controlled harness for authorized recon workflows and safe handoff. See [Architecture](docs/architecture.md), [Web review plane](docs/web-review-plane.md), and [Release readiness](docs/release-readiness.md) for the current product boundary.

---

## Releases and versioning

Outrider ships as a single product under one version:

- Unified project version: `4.0.0` — the Python package and the Claude plugin/content bundle share this number.
- individual skills: versioned as part of the release (no separate per-skill version)
- JSON contract schema version: `1`

The Python package (`pyproject.toml`) and the plugin/content bundle (`.claude-plugin/plugin.json`) are released together at the same version. GitHub release artifacts are checksum-verifiable; the project does not currently claim cryptographic signing or PyPI / Claude Marketplace publication.

See [Release documentation](docs/releases/README.md) for artifacts, checksums, and release notes. See [Release readiness](docs/release-readiness.md) for maintainer-facing release checks.

---

## Current release candidates

Outrider `4.0.0` is prepared as an unsigned release candidate — the first unified release, superseding the separate Python `0.3.0` and plugin/content `3.1.0` version lines. The candidate tag is [`v4.0.0`](https://github.com/Ap6pack/outrider-recon/releases/tag/v4.0.0). The same `SHA256SUMS` file covers all three candidate artifacts (wheel, sdist, and plugin/content bundle); the manual release-candidate workflow does not publish automatically. New work lands under **[Unreleased]** in the [changelog](CHANGELOG.md).

---

## Documentation

| Guide | Purpose |
| --- | --- |
| [Installation](docs/installation.md) | Claude skills, Python CLI, web extras, and MCP setup |
| [Usage](docs/usage.md) | Commands, prompts, and operator workflows |
| [Architecture](docs/architecture.md) | Responsibility boundaries and deterministic controls |
| [Capabilities](docs/capabilities.md) | Complete capability inventory |
| [Coverage](docs/coverage.md) | Practitioner coverage by workflow and engagement phase |
| [Web control plane](docs/web-review-plane.md) | Local control interface with guarded run creation, scope management, scope checks, and workflow-state transitions |
| [Contracts](contracts/README.md) | Skill request/result interchange |
| [MCP server](mcp-server/README.md) | Optional policy-gated enrichment server |
| [Release documentation](docs/releases/README.md) | Versions, artifacts, and checksum verification |
| [Release readiness](docs/release-readiness.md) | Maintainer release checks and readiness status |
| [Security](SECURITY.md) | Authorization and prohibited-use boundaries |

Key architecture decisions are captured in [docs/adr/](docs/adr/), including run state, evidence integrity, approvals, MCP boundaries, contracts, finding promotion, and guarded web control-plane increments. Additional material lives in [docs/methods/](docs/methods/), [docs/reference/](docs/reference/), [examples/](examples/), and [tests/smoke-test-prompts.md](tests/smoke-test-prompts.md).

---

## Project structure

```text
outrider-recon/
├── skills/                  # Claude skills and shared run guidance
├── outrider/                # Python CLI and deterministic local controls
├── mcp-server/              # Optional MCP enrichment server
├── contracts/               # Skill request/result schemas and docs
├── docs/                    # Installation, usage, architecture, ADRs, releases
├── examples/                # Walkthroughs and sanitized output examples
├── tests/                   # Smoke prompts and automated tests
├── assets/                  # README and project assets
├── SECURITY.md              # Authorization and prohibited-use posture
└── README.md                # Public landing page and documentation hub
```

---

## Authorization and security

Outrider is for assets you own or have written authorization to assess, such as red-team rules of engagement, bug-bounty in-scope assets, ASM contracts, and internal security assessments.

The project is built around read-only recon and safe handoff. It explicitly excludes unauthorized testing, credential abuse, destructive validation, malware, persistence, evasion, uncontrolled exploitation, and internal post-exploitation. Deterministic Python controls and optional MCP policy checks help keep local decisions aligned with scope, state, approval, and evidence requirements.

See [SECURITY.md](SECURITY.md) for the full security posture and prohibited-use boundaries.

The local portal now guides new engagements through scope review, explicit scope confirmation, Begin Discovery, and server-derived next-action cards. It still does not provide task-oriented discovery execution, automatic evidence capture, or Claude execution in the browser.

---

## About

Outrider codifies offensive-OSINT and external attack-surface tradecraft into Claude-native skills, deterministic controls, governed agent-to-agent orchestration, and reviewable evidence workflows. It is engagement-platform agnostic: slot it into the ASM, ticketing, asset-graph, bug-bounty, or pentest workflow you already use, and hand its findings off to validation and pen-testing.

**Author:** [Ap6pack](https://github.com/Ap6pack)
**Forked from:** [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT)
**Original framework:** [SnailSploit/offensive-checklist](https://github.com/SnailSploit/offensive-checklist) (v1.x)
**Inspired by:** [Bellingcat's Online Investigations Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) · [IntelTechniques](https://inteltechniques.com/tools/) · [OSINT Framework](https://osintframework.com/)
**Tool inventory:** [ProjectDiscovery](https://github.com/projectdiscovery) · [Six2dez reconftw](https://github.com/six2dez/reconftw) · [SecLists](https://github.com/danielmiessler/SecLists) · [Assetnote Wordlists](https://wordlists.assetnote.io/)
**License:** [MIT](LICENSE) — use freely, attribution appreciated.

> _Raw recon tells you what exists. Outrider helps decide what matters first._
