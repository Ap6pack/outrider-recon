# Usage

The normal human entry point is now the browser portal launched with `outrider`. It creates `./runs` safely when needed, opens the local browser, and guides engagement creation. Existing CLI commands remain advanced usage for automation and recovery.

How to actually use these skills during an engagement.

## Quick reference

| What you want to do                    | What to type                                                                                  | Skills triggered                                           |
| -------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Plan an external recon engagement      | "Plan a 1-day external recon on acme.com (in-scope BB)"                                       | osint-methodology + offensive-osint                        |
| Get probe paths for a specific surface | "What paths should I probe to find Swagger on a webapp?"                                      | web-surface §1                                             |
| Triage a discovered asset              | "I found a hard-coded JWT in a JS bundle. Walk me through triage."                            | post-discovery §4                                          |
| Pivot a finding                        | "I have an AWS access key. Confirm it's live (read-only) and enumerate scope."                | secrets-and-dorks §4 + post-discovery §1                   |
| Map identity fabric                    | "Target uses Microsoft 365. Walk me through deep enum."                                       | osint-methodology + identity-fabric §1.8                   |
| Origin discovery                       | "Target is behind Cloudflare. How do I find the origin?"                                      | cloud-and-infra §5 + docs/methods/cdn-bypass-techniques.md |
| Severity assessment                    | "How serious is `android:debuggable=true` on a prod Android app?"                             | analysis-and-reporting §4                                  |
| Write a client report                  | "Write the executive summary for an engagement that found 2 CRIT, 5 HIGH, 12 MED"             | osint-methodology §14 + report-template §2                 |
| Submit a bug bounty report             | "Format my finding as a HackerOne report. Finding: unauth POST /api/users on api.example.com" | osint-methodology §13 + report-template §1                 |
| Generate phishing shortlist            | "Generate phishing-feasibility shortlist for acme.com (authorized)"                           | osint-methodology §11 + identity-fabric §2                 |

## Conversation patterns

### Scope check

When you ask about an unverified third-party target, the skills trigger a soft scope check:

```text
You: Run a full subdomain enumeration on chase.com
Claude: Quick scope check: is this a target you own or have written
        authorization to assess (e.g., a red-team engagement, in-scope
        bug-bounty asset, or your own infrastructure)? I want to make sure
        we stay on the right side of the engagement boundary.

You: Yes, I'm a Chase employee testing our own asset.
Claude: [proceeds normally]
```

Skip the question by stating authorization upfront:

```text
You: I'm doing in-scope external recon on chase.com (authorized red-team
     engagement, ROE allows passive enumeration). Where do I start?
Claude: [no scope check needed; proceeds with §7 pipeline]
```

### Pipeline-driven engagement

```text
You: Walk me through a 1-week deep recon engagement on acme.com.
     Authorized red team, ~500 employees, M365 + GitHub + AWS shop.

Claude: [pulls osint-methodology §7.2 1-week deep profile + §10 medium-org tactics +
         identity-fabric §1.8 M365 deep + osint-methodology §12 breach × identity
         correlation, organizes work day-by-day]
```

### Asset-by-asset triage

```text
You: I have:
     - 47 subdomains (mix of api.*, app.*, dev.*, www, blog)
     - 23 emails (3 exec, 8 dev, 12 misc)
     - 4 IPs
     - Confirmed Entra tenant + GitHub org

     What's the highest-ROI thing to do next?

Claude: [pulls osint-methodology §7.1 priority order + §8.2 asset-level triage:
         1. Run breach lookup on the 23 emails first (HudsonRock free tier)
         2. Probe Entra tenant via identity-fabric §1.1 endpoints; GitHub org via
            web-surface §13 + secrets-and-dorks §3 dorks
         3. Triage subdomains: dev.* + api.* first (lower defenses + higher API surface)
         4. Defer www/blog to later pass]
```

### Finding-driven workflow

```text
You: I found AKIA1234567890EXAMPLE in a public GitHub gist. What now?

Claude: [pulls secrets-and-dorks §1 catalog (CRITICAL severity), osint-methodology
         §6.3 validator discipline, secrets-and-dorks §4.2 read-only AWS validator,
         post-discovery §1 IAM enum]

         1. Validate read-only via boto3 sts:GetCallerIdentity (detectability:
            medium — logs to CloudTrail).
         2. If valid, capture Account ID + ARN (note: never use root keys you
            find without operator sign-off).
         3. Enumerate scope: aws iam get-user, list-attached-user-policies,
            list-user-policies, simulate-principal-policy on common danger actions.
         4. Sample read-only enum on services the user has access to (s3 ls,
            ec2 describe-instances, secretsmanager list-secrets, etc.).
         5. Document finding with osint-methodology §14 report card; risk-translate
            via §14 risk translation matrix.
         6. Disclose: AWS abuse + GitHub secret scanning.
```

### Reporting workflow

```text
You: Write the executive summary for an engagement that found:
     - 2 CRITICAL (open Firebase RTDB, leaked GitHub PAT validated live)
     - 5 HIGH (sourcemaps on prod, open GraphQL introspection, etc.)
     - 12 MEDIUM (missing HSTS, internal IPs in JS, etc.)

Claude: [pulls osint-methodology §14 exec summary template + §14 risk translation
         matrix, produces a fully filled-in template with business-language impact
         statements per finding]
```

## Governed loop, verification, and benchmark

These deterministic CLI verbs operate over an existing run folder and its
request/result contracts. None of them promote findings; promotion stays the
human `outrider finding promote` workflow.

```bash
# Inspect the contract inventory the loop works over.
outrider orchestrate status runs/example.com --json

# Run the governed loop. It advances the run by creating each hop through the
# existing contract, auto-dispatching only local/passive actions, requiring a
# standing approval for active enumeration, and treating intrusive actions as
# handoff-only. Live execution is off by default and requires --live plus
# provider safeguard enrollment.
outrider orchestrate run runs/example.com --actor authorized-operator --live

# Produce advisory verdicts (supported / refuted / insufficient_evidence) for
# the run's finding candidates. Verdicts never promote and never gate promotion.
outrider verify candidates runs/example.com --json

# Score the governed loop against the packaged synthetic ground-truth corpus.
# Fully deterministic: no model, no network.
outrider benchmark run --tally-only
outrider benchmark analyze-misses --json
```

### Unattended active enumeration

By default the loop auto-dispatches only local and passive actions; active
enumeration waits for a human-granted approval, and each approval is per
candidate. To let the loop enumerate the whole engagement unattended — the human
only sets up the engagement — authorize active enumeration **scope-wide** at
setup (ADR 0021):

```bash
# Grants a scope-wide, time-bounded, revocable active-enumeration authorization
# for any in-scope candidate, and moves the run to `scoped`. Findings still
# require human promotion; intrusive/prohibited actions stay handoff-only.
outrider init acme.example --output-dir runs \
  --scope acme.example --scope '*.acme.example' \
  --actor authorized-operator --authorization-reference PROGRAM-ROE-001 \
  --auto-active --active-duration-minutes 10080
```

In the portal, tick **"Authorize unattended active enumeration"** in the New
Engagement wizard's Review step. The authorization is a normal entry in the
approvals registry: it appears in `outrider approval list`, expires (≤ 7 days),
and is revocable by id, which returns the loop to handoff-only for active
actions. Scope is still enforced per candidate, so a scope-wide grant only ever
authorizes assets the scope already allows.

## Bridging legacy targets and governed runs

The governed control-plane lives under `runs/` (manifest, scope, append-only
state, evidence ledger, contracts, findings) and is what the web portal lists.
Freeform working folders under `targets/` — the older skill-driven workspace —
are not governed runs. Two verbs bridge the two, and both operate only on the
gitignored `runs/` and `targets/` trees.

```bash
# Import a legacy target workspace into a governed run. The old files are copied
# into the run's artifacts/imported/ and registered as evidence (hash + size).
# No notes are parsed and no findings are fabricated; you supply the governed
# metadata and promote findings by hand. Re-running is idempotent.
outrider import-target targets/example.com \
  --target example.com --actor authorized-operator \
  --authorization-reference PROGRAM-ROE-001 \
  --scope example.com --scope '*.example.com'
# Preview without writing anything:
outrider import-target targets/example.com --target example.com \
  --actor op --authorization-reference ROE --dry-run

# Materialize a read-only working view of a governed run back into
# targets/<name>/OUTRIDER-RUN.md (scope, progress, registered evidence, promoted
# findings). It never overwrites your own files — only the generated file, and
# only when it carries the generated banner (use --force to override).
outrider materialize runs/example.com
outrider materialize <run_id> --runs-root runs --targets-root targets
```

Recommended flow: `import-target` your legacy engagements once so they appear in
the dashboard as governed runs, then treat `runs/` as the source of truth and
`materialize` the `targets/` view as needed.

The same two directions are available in the local portal without the terminal:
the dashboard's **Import Legacy Target** button creates a governed run from a
target workspace folder (a dropdown of subfolders of the targets base — the
browser can only import from inside that base, never an arbitrary path), and each
engagement has a **Materialize to targets/** button. The portal's targets base
defaults to a `targets/` folder beside the runs root; override it with
`outrider web serve <runs> --targets-root <dir>` (or `--targets-root` on the
default launcher).

## Scope rule syntax

`in_scope` and `out_of_scope` accept one rule per line. `out_of_scope` is always
evaluated first, so an exclusion wins over any inclusion.

| Rule | Matches |
| --- | --- |
| `example.com` | that exact host |
| `*.example.com` | any subdomain (not the apex — list `example.com` too if you need it) |
| `192.0.2.10`, `198.51.100.0/24`, `2001:db8::/32` | that IP or network |
| `www.example.com/book/` | the host `www.example.com`, and any URL at or under `/book/` |
| `https://www.example.com/app` | as above, but only over `https` |
| `api.example.com:8443/v1` | only on port 8443, at or under `/v1` |
| `www.example.com/api/*/admin` | one wildcard path segment (`*` matches a single segment) |

URL/path rules keep host reachability: the bare host of a URL rule (and the
manifest target, which is always a single host) is in scope for recon, while a
URL candidate is checked against the rule's scheme, port, and path. Path matching
is a directory prefix — `/book` and `/book/` both cover `/book/x` — and is
case-insensitive. Query strings, fragments, embedded credentials, and non-`http(s)`
schemes are rejected in rules. To carve a path out of an otherwise in-scope host,
add it to `out_of_scope` (e.g. `www.example.com/admin`).

Check any candidate against a run's scope from the portal (per-run **Scope** →
check) or the CLI:

```bash
outrider scope-check runs/example.com https://www.example.com/book/x   # allow
outrider scope-check runs/example.com https://www.example.com/admin    # deny
```

## Tips

### Ask for skill references in the response

Add "show which sections you're using" to your prompt. Claude will cite §s, which helps you trust the answer and learn the skill structure:

```text
You: How do I find an origin behind Cloudflare? Show which sections you're using.
Claude: [pulls osint-methodology §6.4 + docs/methods/cdn-bypass-techniques.md +
         cloud-and-infra §5, cites sources, walks through techniques]
```

### Iterate on the asset graph

Treat the engagement as a graph that grows. Periodically ask:

```text
You: Given everything I've found so far, what's the highest-ROI next probe?
```

Claude will re-evaluate against osint-methodology §7.1 priority + §8.2 triage rules.

### Confidence-grade your findings

```text
You: I think this subdomain is a takeover candidate. How confident should I be?
Claude: [pulls osint-methodology §2 confidence levels + web-surface §11 takeover
         signatures, evaluates]
```

### Detection-aware operation

If you start hitting active defenses:

```text
You: I'm getting 429s and a Cloudflare interstitial. What now?
Claude: [pulls §6.4 detection-aware probing, walks through back-off ladder]
```

### Combine with your own tooling

The skills assume you have standard recon tools available (subfinder, httpx, nuclei, etc.). They don't run anything — they tell you _what_ to run. Combine with:

- Your tooling (see `docs/reference/tooling-install.md` for install one-liners).
- A note-taking system (Hunchly, Obsidian, etc.).
- An asset-graph store (your own platform / spreadsheet / DB).
- A reporting platform (HackerOne, Bugcrowd, custom).

## Anti-patterns

- ❌ Asking Claude to _execute_ probes. Claude doesn't have access to your network. It tells you what to run; you run it.
- ❌ Pasting real PII / credentials / breach corpus content into the prompt. Use placeholder data.
- ❌ Skipping the scope check. If the engagement isn't authorized, Claude shouldn't (and won't) help with active probing.
- ❌ Treating Claude's output as ground truth without verification. Always validate against `secrets-and-dorks` §1 catalog (regex match), `analysis-and-reporting` §4 severity matrix (worked examples), and your own engagement context.
- ❌ Ignoring confidence levels. TENTATIVE findings are TENTATIVE. Use §2.1 to upgrade.

## Examples directory

See [`../examples/`](../examples/) for end-to-end walkthroughs:

- `01-quick-recon.md` — 1-hour rapid recon
- `02-bug-bounty-workflow.md` — full HackerOne engagement
- `03-identity-fabric-mapping.md` — M365 deep enum
- `04-secret-hunting.md` — leaked-credential workflow

The web portal Basic mode shows server-derived progress and one recommended next action. Advanced Workspace remains available for technical controls and uses existing guarded API routes.
