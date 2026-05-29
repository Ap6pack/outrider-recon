# Pull Request

## Description

Brief summary of what this PR changes.

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New section / capability (non-breaking change which adds functionality)
- [ ] Wordlist / catalog expansion (non-breaking)
- [ ] Vendor fingerprint / secret pattern / dork addition (non-breaking)
- [ ] Documentation update
- [ ] Renumbering / restructuring (potentially breaking)
- [ ] Test addition (smoke-test prompt)

## Affected skills

- [ ] `osint-methodology`
- [ ] `offensive-osint` (router)
- [ ] `recon-asset-discovery`
- [ ] `web-surface`
- [ ] `identity-fabric`
- [ ] `secrets-and-dorks`
- [ ] `post-discovery`
- [ ] `cloud-and-infra`
- [ ] `people-breach-intel`
- [ ] `analysis-and-reporting`
- [ ] `report-template`
- [ ] Repo infrastructure only (docs, CI, etc.)

## Affected sections (if applicable)

- skill: __________ §____

## Checklist

- [ ] My change is OSINT-only (no active exploitation, post-exploit, malware tradecraft).
- [ ] I updated `CHANGELOG.md` under `[Unreleased]`.
- [ ] I updated `docs/capabilities.md` (if I added a capability).
- [ ] I added trigger phrases to the YAML frontmatter (if I added a new triggerable concept).
- [ ] I added a self-test prompt to `tests/smoke-test-prompts.md` (if I added a new capability).
- [ ] Severity / detectability / confidence tags are consistent with existing rubrics.
- [ ] I tested locally (installed the modified skill in Claude Code and verified the relevant prompts).
- [ ] My commits follow the format `<type>(<scope>): <subject>`.

## Sample prompt that exercises this change

```
[paste a prompt here that triggers the new content]
```

## Expected response

[describe what Claude should now do for that prompt]

## Related issues

Closes #___
References #___

## Additional notes

(Any breaking changes, migration notes, or context for reviewers.)
