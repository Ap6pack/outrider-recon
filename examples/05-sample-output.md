# Example 05: Sanitized Outrider Recon Output

> This is a fictional, redacted example showing the kind of output Outrider should make easy to generate. It is not a real target and does not include exploit instructions.

---

## Engagement context

| Field | Value |
|---|---|
| Target | `acme.example` |
| Scope | `*.acme.example`, excluding `legacy.acme.example` and `*.staff-only.acme.example` |
| Engagement type | Authorized external recon / bug-bounty style triage |
| Boundary | Read-only recon, no destructive validation, no post-exploitation |

---

## Ranked surface

### P1 — investigate first

#### `https://api.acme.example`

**Why it matters**

- Live API host with OpenAPI schema exposed.
- Schema contains user, account, order, and admin-like paths.
- JavaScript bundles reference object-shaped API routes.
- Public disclosed-report intelligence maps similar surfaces to IDOR, mass assignment, and broken object-level authorization patterns.

**Recommended handoff**

- `hunt-api-misconfig`
- `hunt-idor`
- Burp Repeater authorization testing
- Manual review of object-level authorization rules

**Safe next step**

Verify authentication posture and object ownership checks without modifying production data.

---

#### `https://sso.acme.example`

**Why it matters**

- Identity-provider surface discovered.
- OIDC metadata available.
- Tenant and federation hints found.
- Employee and domain patterns may support identity-fabric mapping.

**Recommended handoff**

- `identity-fabric`
- SSO/OIDC review
- OAuth redirect URI and client-id inventory

**Safe next step**

Collect metadata, document configuration exposure, and avoid credential testing or user enumeration outside program rules.

---

### P2 — useful, but not first

#### `https://dev.acme.example`

**Why it matters**

- Non-production naming signal.
- Interesting JavaScript paths.
- No confirmed sensitive exposure yet.

**Recommended handoff**

- JS endpoint extraction
- Source-map checks
- Hidden admin/API route review

---

### Kill / low priority

#### `https://cdn.acme.example`

**Why it matters**

- Static asset host only.
- No dynamic endpoints found.
- No interesting headers, forms, APIs, or JS route leaks.

---

## Finding card example

```text
[HIGH] api.acme.example exposes OpenAPI schema
Confidence: Confirmed
Detectability: Low
Evidence:
- GET https://api.acme.example/openapi.json returned HTTP 200
- Schema includes /users/{id}, /accounts/{accountId}, /orders/{orderId}
- Response saved with UTC timestamp and SHA-256 hash

Why it matters:
- API schema reveals object identifiers and hidden write endpoints.
- Public report intelligence maps similar schemas to IDOR, mass assignment, and broken authorization patterns.
- The exposed schema gives a high-quality starting point for safe authorization review.

Recommended handoff:
- hunt-api-misconfig
- hunt-idor
- Burp Repeater authorization testing

Safe next step:
- Verify whether authentication is required.
- Check whether object IDs are user-scoped using owned test accounts only.
- Do not mutate production data without explicit authorization.
```

---

## Technique card example

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
- Confirm docs exposure.
- Identify object-shaped paths.
- Use owned test accounts only.
- Compare same endpoint behavior across account A and account B if program rules allow.
- Stop before destructive writes or privilege changes unless explicitly authorized.

Confidence: Firm
Value: High
Handoff: hunt-api-misconfig, hunt-idor
```

---

## External recon report summary

```text
Executive Summary

Outrider identified 3 high-value external recon leads across the target's API and identity surfaces. The highest-priority item is an exposed OpenAPI schema on api.acme.example that reveals user, account, and order object paths. Public disclosed-report intelligence maps similar surfaces to IDOR, mass assignment, and broken authorization testing paths.

No destructive validation was performed. Recommended next steps are limited to authorized, owned-account testing and manual review in Burp/ZAP or a dedicated bug-hunting workflow.
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

