---
name: New technique / vendor / pattern
about: Add a new vendor product fingerprint, secret pattern, dork, or wordlist entry
title: '[NEW] '
labels: enhancement, technique
assignees: ''
---

## Type of addition

- [ ] Vendor product fingerprint (target: web-surface §10)
- [ ] Secret pattern (target: secrets-and-dorks §1)
- [ ] Dork template (target: secrets-and-dorks §2)
- [ ] Wordlist entry (target: recon-asset-discovery §2)
- [ ] Cloud-native service fingerprint (target: cloud-and-infra §1)
- [ ] Identity-fabric endpoint (target: identity-fabric §1)
- [ ] Validator (target: secrets-and-dorks §4)
- [ ] Attack-path hint template (target: analysis-and-reporting §3)
- [ ] Severity-matrix worked example (target: analysis-and-reporting §4)
- [ ] Other: ___________

## Concrete addition

Paste the exact content to add. Examples:

**For a vendor fingerprint:**
```
| Vendor | Fingerprint paths | Notes |
|---|---|---|
| **<Product Name>** | `/path/to/version-disclosure`, `/api/v1/info` | CVE-XXXX-XXXX (KEV-listed). |
```

**For a secret pattern:**
```
| <#> | <Pattern Name> | `<regex>` | <SEVERITY> | <category> |
```

**For a dork:**
```
site:{domain} <dork-content>
```

## Validation

- [ ] Tested against a real (authorized) target — does the fingerprint actually work?
- [ ] False-positive rate considered? (For regex patterns.)
- [ ] CVE associations included where relevant?

## Source / attribution

Where did you find this? (Vendor docs, CVE advisory, your own research, etc.)

## Severity / detectability proposal

What severity should findings of this pattern carry? What's the detectability?

## Self-test prompt

Paste a sample prompt that should now trigger the new content.
