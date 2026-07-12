---
name: report-template
description: "Autonomous report generation from collected findings. Produces bug bounty submissions, client deliverables, and vulnerability reports using the standard finding schema."
version: 1.0.0
triggers:
  - generate report
  - write report
  - write findings
  - bug bounty submission
  - create deliverable
  - vulnerability report
  - submit finding
  - report template
---

# Report Template

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and deliverable context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** Report generation, bug bounty submission, vulnerability write-up, or client deliverable creation is needed.

**Execute:**

1. Collect all findings from the current engagement — pull from sidecar JSON files if available (`analysis-and-reporting` §6).
2. For bug bounty submissions: populate the Bug Bounty Report Template (§1) for each finding.
3. For client deliverables: populate the Client Report Template (§2) covering all findings.
4. Auto-fill severity, confidence, and attack-path hints from `analysis-and-reporting` §4 and §3.
5. Include reproduction steps with evidence (URL + UTC timestamp + SHA-256).
6. Apply risk translation for executive audience (see `osint-methodology` §14).

**Output:** Completed report per §1 or §2 template, ready for submission or delivery.

**Severity rules:** Use severity from the finding schema. Include CVSS v3 vector + score for bug bounty.

**Gating rules:** Never include raw credentials in reports — truncate to last 4 characters. Redact PII. Include encrypted credential bundle separately if needed.

**Chain to:** This is typically the final skill in the pipeline. Receives findings from all other sub-skills via `analysis-and-reporting` sidecar coordination.

---

## 1. Bug Bounty Report Template

```text
Title: [{severity}] [{component}] {brief description}

## Overview
**Vulnerability Type:** {e.g., XSS, CSRF, SQL Injection, Exposed Credentials, Misconfiguration}

## Description
{2-3 sentences: what the vulnerability is and why it matters}

## Steps To Reproduce
1. {step with exact URL/endpoint}
2. {step with payload or action}
3. {step showing the result}
4. {additional steps as needed}

## Proof of Concept
{The most important section. Sanitized HTTP request/response, screenshot, or command output.
 Include: URL + UTC timestamp + tool used. Truncate secrets to last 4 chars.}

## Impact
{What data/users/functions are at risk. Business-language impact statement.}

## Severity
{CVSS v3 vector + score + 1-sentence justification}

## Suggested Fix
{Concrete, actionable remediation recommendation}

## Supporting Material
{Screenshots, logs, WARC archives, SHA-256 hashes of downloaded artifacts}

## Additional Information
{Engagement context, related findings, references (CVE IDs, advisory URLs)}
```

**Platform notes:**

- HackerOne: CVSS-based severity
- Bugcrowd: VRT taxonomy (P1–P5)
- Intigriti / YesWeHack: Similar to HackerOne
- Unprogrammed targets: check `/.well-known/security.txt` → `security@<target>` → WHOIS abuse contact → CERT/CC. 90-day disclosure window.

---

## 2. Client Report Template

```text
# Engagement Report: {target} — {date range}

## Executive Summary
- Engagement type: {red team / bug bounty / ASM / ad-hoc}
- Scope: {domains, IP ranges, applications}
- Duration: {start — end}
- Top findings: {3-5 highest-severity findings with business impact + remediation effort}

## Aggregate Metrics
- Total assets discovered: {count by type}
- Findings by severity: {CRITICAL: N, HIGH: N, MEDIUM: N, LOW: N, INFO: N}
- Live credentials confirmed: {count}

## Findings

### Finding {N}: {title}
- **ID:** {stable hash or UUID}
- **Severity:** {CRITICAL/HIGH/MEDIUM/LOW/INFO}
- **Confidence:** {TENTATIVE/FIRM/CONFIRMED}
- **Asset:** {typed key, e.g., sub:api.example.com}
- **Category:** {e.g., SECRET_LEAK, OPEN_GRAPHQL_API, SSO_EXPOSURE}
- **Discovered:** {UTC ISO8601}
- **Description:** {2-5 sentences}
- **Evidence:** {URL + tool + screenshot + raw HTTP (truncated 2 KiB) + SHA-256}
- **Reproduction steps:** {numbered, copy-pasteable}
- **Business impact:** {risk translation for non-technical audience}
- **Remediation:** {immediate / short-term / long-term}
- **Attack path hint:** {from analysis-and-reporting §3 templates}
- **References:** {CVE-ID, advisory URL, vendor doc}

{Repeat for each finding}

## Recommended Next Steps
{Timeline-based recommendations with priority}

## Reproduction Package
- `run-log.jsonl` — timestamped event log
- `assets.db` — discovered assets
- `findings.db` — all findings
- `evidence/` — screenshots, HTTP captures, downloads (with .sha256)
- `re-test-script.sh` — re-validation script for remediated findings
```

## Structured Outrider run contract

Follow the shared run-contract instructions in `../_shared/run-contract.md`.

- Contract skill identifier: `report-template`.
- Consume `skill_request` version 1 and produce `skill_result` version 1 when participating in an Outrider run.
- Use evidence IDs for all claims; do not cite unregistered local paths as claim evidence.
- Discoveries are observations and do not expand scope or approval.
- Do not claim final finding validation; use `finding_candidate` only when a human-reviewed candidate should be handed off.
- Do not directly edit `manifest.json`, `scope.yaml`, `run.jsonl`, `evidence.jsonl`, or `approvals.jsonl`.
- Use policy-gated MCP with the explicit `run_dir`; the Python control layer and MCP boundary must reevaluate current controls.
