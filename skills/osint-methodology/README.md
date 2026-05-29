# `osint-methodology` skill

The "how to think" reference for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `osint-methodology` |
| Version | 2.2 |
| Lines | ~420 |
| Sections | 15 (Behavioral Contract + sections 0-14) |
| Companion skill | [`offensive-osint`](../offensive-osint/) |

## What's in it

| Section | Title |
|---|---|
| Behavioral Contract | When/how the skill activates and chains |
| 0 | When to Use / When NOT |
| 1 | Authorization & Legal Posture |
| 2 | Confidence Levels |
| 3 | Output Format |
| 4 | Source Hygiene & Citations |
| 5 | Do NOT |
| 6 | OpSec (sock puppets, detectability tagging, validator discipline, detection-aware probing) |
| 7 | External Red-Team Recon Pipeline (5-stage pipeline, priority order, time budgeting) |
| 8 | Asset Graph Discipline (29 typed assets in 9 categories, triage rules — see docs/architecture.md for the typed-edge graph) |
| 9 | Findings Rubric & Severity Mapping (anchors + escalation rules) |
| 10 | Pivot Modes & Scale Tactics |
| 11 | Implementation: Companion Skill Pointers |
| 12 | Breach x Identity Correlation |
| 13 | Bug Bounty Submission & Responsible Disclosure |
| 14 | Client Deliverable Templates |

## When this skill triggers

Auto-triggers on prompts containing any of ~55 trigger phrases. Common ones:

- `external recon`, `external red team`, `bug bounty recon`, `attack surface management`, `ASM`, `perimeter recon`
- `OSINT methodology`, `recon methodology`, `target reconnaissance`, `asset discovery`, `attack path`
- `identity fabric`, `SSO discovery`, `IdP fingerprinting`, `M365 enumeration`
- `phishing infrastructure`, `pretext development`, `bug bounty submission`, `responsible disclosure`
- `client report`, `exec summary`, `risk translation`
- `confidence upgrade`, `time budget`, `engagement profile`, `asset triage`
- `detection-aware probing`, `back-off strategy`, `persona rotation`
- `WAF bypass`, `CDN bypass`, `origin discovery`
- `vulnerability prioritization`, `CVE prioritization`, `EPSS`, `CISA KEV`
- `threat actor investigation`, `attribution`

Full trigger list in the SKILL.md frontmatter.

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/osint-methodology/SKILL.md

# Or attach to a Claude.ai project / Claude API system prompt
# (paste contents of SKILL.md as project knowledge)
```

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md) to verify skill behavior after install. Methodology-targeted prompts are tagged in the test file.

## License

MIT — see [LICENSE](../../LICENSE).
