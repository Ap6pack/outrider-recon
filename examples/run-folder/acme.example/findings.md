# Finding Cards — acme.example

```text
[HIGH] api.acme.example exposes OpenAPI schema

Confidence:
- Confirmed

Evidence:
- GET https://api.acme.example/openapi.json returned HTTP 200
- Schema includes /users/{id}, /accounts/{accountId}, /orders/{orderId}

Why it matters:
- API schema reveals object identifiers and hidden routes.
- Similar public reports often involve IDOR/BOLA, mass assignment, or broken authorization.
- The schema gives a high-quality map for safe manual review.

Recommended handoff:
- API authorization review
- Proxy-assisted manual validation
- ASM or client tracking item

Safe next step:
- Verify whether authentication is required.
- Check object ownership using authorized test accounts only.
- Stop before destructive writes, privilege changes, or data modification unless explicitly authorized.
```
