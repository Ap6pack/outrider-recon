# Example 05: Sanitized Outrider Recon Output

> Fictional, redacted sample output showing how Outrider should turn external recon into prioritized, evidence-backed leads. This is not a real target and does not include exploit instructions.

---

## What Outrider found

| Category                | Result                                                                            |
| ----------------------- | --------------------------------------------------------------------------------- |
| Target                  | `acme.example`                                                                    |
| Scope                   | `*.acme.example`, excluding `legacy.acme.example` and `*.staff-only.acme.example` |
| Engagement type         | Authorized external recon / bug-bounty style triage                               |
| Boundary                | Read-only recon, no destructive validation, no post-exploitation                  |
| High-value leads        | 3                                                                                 |
| Top priority            | `<https://api.acme.example`>                                                      |
| Primary reason          | Exposed OpenAPI schema with user/account/order object paths                       |
| Public disclosure match | IDOR, mass assignment, broken object-level authorization patterns                 |

---

## Executive summary

Outrider identified three high-value external recon leads across the target's API, identity, and non-production surfaces. The strongest lead is an exposed OpenAPI schema on `api.acme.example` that reveals object-shaped user, account, and order endpoints.

The finding was not treated as a vulnerability by itself. Outrider ranked it as a high-value lead because similar API documentation exposures in public bug-bounty disclosures often create good starting points for safe authorization review, IDOR testing, and mass-assignment review.

No destructive validation was performed. Recommended next steps are limited to authorized, owned-account testing and manual review in a proxy-assisted testing workflow.

---

## Ranked surface

### P1 — investigate first

#### `https://api.acme.example`

#### What was observed

- Live API host.
- OpenAPI schema available at `/openapi.json`.
- Schema includes `/users/{id}`, `/accounts/{accountId}`, and `/orders/{orderId}` paths.
- JavaScript bundles reference related object-shaped API routes.
- Endpoint names resemble prior disclosed report patterns involving IDOR, mass assignment, and broken object-level authorization.

#### Why it matters

An exposed API schema gives an operator a high-quality map of the application. The schema is not automatically a reportable vulnerability, but it can expose routes, object identifiers, hidden methods, admin-like paths, and request models that make authorization review much more efficient.

#### Public disclosure intelligence

Comparable public bug-bounty reports commonly map this kind of surface to:

- object-level authorization failures,
- account or tenant boundary mistakes,
- mass-assignment through undocumented request fields,
- unauthenticated or under-protected write methods,
- inconsistent authorization across API versions.

#### Recommended handoff

- API misconfiguration review.
- IDOR / BOLA authorization testing.
- Burp Repeater review using owned test accounts only.
- Manual comparison of account A vs account B object access if program rules allow.

#### Safe next step

Verify authentication requirements and object ownership checks using only authorized test accounts. Do not modify production data or attempt privilege changes unless explicitly allowed by the program or rules of engagement.

---

#### `https://sso.acme.example`

#### What was observed for SSO

- Identity-provider surface discovered.
- OIDC metadata available.
- Tenant and federation hints found.
- Domain and employee-pattern signals support identity-fabric mapping.

#### Why identity exposure matters

Identity surfaces often define the real boundary of an external attack surface. Even when no vulnerability is present, metadata can help defenders understand exposed authentication flows, federated domains, OAuth clients, and where future review should focus.

#### Recommended identity handoff

- SSO/OIDC configuration review.
- OAuth redirect URI and client-id inventory.
- Identity-fabric mapping.

#### Safe identity next step

Collect metadata and document configuration exposure. Avoid password attempts, credential testing, social engineering, MFA fatigue, or user enumeration outside written authorization.

---

### P2 — useful, but not first

#### `<https://dev.acme.example`>

#### What was observed

- Non-production naming signal.
- Interesting JavaScript paths.
- No confirmed sensitive exposure yet.

#### Why it matters

Development and staging hosts often have weaker controls or forgotten routes, but this host does not yet have enough signal to outrank the exposed API schema or identity surface.

#### Recommended handoff

- JavaScript endpoint extraction.
- Source-map checks.
- Hidden admin/API route review.

---

### Kill / low priority

#### `<https://cdn.acme.example`>

#### What was observed

- Static asset host only.
- No dynamic endpoints found.
- No interesting headers, forms, APIs, or JavaScript route leaks.

#### Why it matters

This asset should be kept in inventory but deprioritized for manual review unless new signals appear later.

---

## Finding card

```text
[HIGH] api.acme.example exposes OpenAPI schema

Asset:
- https://api.acme.example/openapi.json

Confidence:
- Confirmed

Detectability:
- Low

Evidence:
- GET https://api.acme.example/openapi.json returned HTTP 200
- Schema includes /users/{id}, /accounts/{accountId}, /orders/{orderId}
- Response saved with UTC timestamp and SHA-256 hash

Why it matters:
- API schema reveals object identifiers and hidden write endpoints.
- Public report intelligence maps similar schemas to IDOR, mass assignment, and broken authorization patterns.
- The exposed schema gives a high-quality starting point for safe authorization review.

Public disclosure intelligence:
- Similar reports commonly involve object-level authorization gaps.
- Similar reports often rely on comparing owned test accounts rather than destructive writes.
- Severity depends on whether authorization bypass, cross-account read, or unsafe write behavior is confirmed.

Recommended handoff:
- API authorization review
- IDOR / BOLA testing
- Proxy-assisted manual validation

Safe next step:
- Verify whether authentication is required.
- Check object ownership using owned test accounts only.
- Stop before destructive writes, privilege changes, or data modification unless explicitly authorized.
```

---

## Technique card

```text
Technique Card: OpenAPI schema → object-level authorization review

Matched because:
- OpenAPI schema was exposed.
- Schema contains user/account/order object paths.
- Endpoint names resemble prior disclosed report patterns involving IDOR and mass assignment.

Prior disclosure pattern:
- Exposed API docs often reveal hidden or poorly tested endpoints.
- Object IDs in documented routes can guide authorization testing.
- Similar reports commonly succeed when ownership checks are missing across tenant/account boundaries.

Recommended safe probes:
- Confirm documentation exposure.
- Identify object-shaped paths.
- Use owned test accounts only.
- Compare same endpoint behavior across account A and account B if program rules allow.
- Stop before destructive writes or privilege changes unless explicitly authorized.

Confidence: Firm
Value: High
Handoff: API authorization review, IDOR/BOLA review, proxy-assisted manual validation
```

---

## Report-ready summary

```text
Outrider identified an exposed OpenAPI schema on api.acme.example. The schema reveals user, account, and order object paths and provides a useful map for safe authorization review. Public disclosed-report intelligence shows similar surfaces commonly lead to IDOR, mass assignment, and broken object-level authorization findings when ownership checks are missing.

No exploitation or destructive validation was performed. Recommended next steps are limited to authorized, owned-account testing and manual review in Burp/ZAP or an equivalent proxy-assisted workflow.
```

---

## Planned harness mapping

Future `outrider` CLI output should be able to generate files like:

```text
runs/acme.example/
├── scope.yaml
├── run.jsonl
├── assets.json
├── web_surface.json
├── identity_fabric.json
├── bb_intel.json
├── findings.md
├── technique_cards.md
├── surface.md
└── report.md
```

The important part is not the file names. The important part is the workflow: raw recon should become ranked leads, evidence, safe next steps, and handoff-ready output.
