# Technique Cards — acme.example

```text
Technique Card: OpenAPI schema → object-level authorization review

Matched because:
- OpenAPI schema was exposed.
- Schema contains user/account/order object paths.
- Endpoint names resemble common public disclosure patterns involving authorization review.

Prior disclosure pattern:
- Exposed API docs often reveal hidden or poorly tested endpoints.
- Object IDs in documented routes can guide safe authorization testing.
- Similar reports commonly succeed when ownership checks are missing across account or tenant boundaries.

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
