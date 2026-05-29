# `offensive-osint` skill

The "what to reach for" operational arsenal for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `offensive-osint` |
| Version | 2.1.1 |
| Lines | ~80 |
| Headings | 5 (Behavioral Contract, Sub-skill map, Session start checklist, Hard rules, plus frontmatter) |
| Role | Router — dispatches to 9 sub-skills by task type |
| Companion skill | [`osint-methodology`](../osint-methodology/) |

## Architecture

`offensive-osint` is an 80-line router. It produces no findings itself — it identifies the current task, matches it to a sub-skill, and delegates execution.

### Sub-skills dispatched to

| Sub-skill | Covers |
|---|---|
| `recon-asset-discovery` | Subdomains, ASN/BGP, DNS, CT, WHOIS/RDAP, geospatial, regional engines |
| `web-surface` | Swagger/GraphQL paths, curl probes, Wayback, Postman, endpoint scoring |
| `identity-fabric` | IdP fingerprinting, Entra/Okta/ADFS/SAML, M365 deep enum, LinkedIn |
| `secrets-and-dorks` | Secret regexes, dork corpus, GitHub code-search dorks, read-only validators |
| `post-discovery` | JWT triage, AWS IAM enum, GitHub/Slack post-credential workflows |
| `cloud-and-infra` | Cloud-native fingerprints, K8s/container, CI/CD exposure, infra OSINT |
| `people-breach-intel` | Username/email/phone, breach data, HudsonRock, crypto, media, Telegram |
| `analysis-and-reporting` | Scoring rubrics, attack-path hints, severity matrix, AI-assisted OSINT |
| `report-template` | Bug-bounty report scaffold |

## When this skill triggers

Auto-triggers on prompts containing phrases like `external recon`, `bug bounty`, `attack surface management`, `reconnaissance`, `asset discovery`, `start recon`, `new target`, and others listed in the SKILL.md frontmatter.

The companion `osint-methodology` skill shares several triggers and is co-loaded at session start.

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/offensive-osint/SKILL.md
cp scripts/secret_scan.py ~/.claude/skills/offensive-osint/scripts/secret_scan.py

# Or attach to a Claude.ai project / Claude API system prompt
```

## Helper script

[`scripts/secret_scan.py`](scripts/secret_scan.py) — stdlib-only Python scanner mirroring the secret-pattern catalog. Run standalone:

```bash
python3 scripts/secret_scan.py path/to/repo/        # scan a directory tree
python3 scripts/secret_scan.py file1 file2 file3    # scan specific files
cat my.log | python3 scripts/secret_scan.py         # pipe stdin
```

Output: JSONL — one finding per line — `jq`-friendly.

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md). Arsenal-targeted prompts are tagged in the test file.

## License

MIT — see [LICENSE](../../LICENSE).
