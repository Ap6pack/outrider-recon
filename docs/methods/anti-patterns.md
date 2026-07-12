# Anti-Patterns & Common Failure Modes

> Operational tradecraft reference. Common mistakes in OSINT engagements
> and how to avoid them. Extracted from skill files for clean separation.

---

## General OSINT Anti-Patterns

- **Single-source attribution.** Rule of three.
- **Trusting vendor labels as ground truth.** Labels are hypotheses.
- **Favicon-hash = ownership.** Shared infra, shared CMS, shared CDN all produce matches.
- **Snippet-only dork as CONFIRMED.** TENTATIVE until visited.
- **Pasting real PII / creds into cloud LLMs.** Local models only.
- **Mirror-imaging the threat actor.** They don't think like you.
- **Attribution by IP geolocation.** VPNs and residential proxies exist.
- **Ignoring CT-log lag.** Absence ≠ doesn't exist; lag can be minutes to hours.
- **Counting Wayback as "the site at time T."** Best-effort; many requests fail.
- **Letting the asset graph carry untyped strings.** Every discovery is an asset.
- **Skipping the scope check.** Ask once when in doubt.
- **Forgetting UTC.** Local time creates correlation bugs.
- **Continuing to probe after a WAF block.** Back off per OpSec back-off ladder.
- **Skipping confidence-upgrade documentation.** TENTATIVE needs a path to CONFIRMED.
- **Treating exec-summary as an afterthought.** Plan deliverables at engagement start.

---
