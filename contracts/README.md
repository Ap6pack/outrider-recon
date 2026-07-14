# Outrider skill contracts

Outrider skill contracts are local run artifacts under `contracts/requests/` and `contracts/results/`. They are deterministic JSON interchange records between Claude skills and the Python control layer. They are not scope authority, approval authority, authenticated identity, evidence-registry records, tool permission, or validated findings.

- `skill-request-v1.schema.json` documents request shape for `schema_version: 1`.
- `skill-result-v1.schema.json` documents result shape for `schema_version: 1`.

The Python validator is the enforcement layer. It reloads the manifest, durable state, scope, approval records, and evidence registry on every validation.

## Finding record v1

`finding-v1.schema.json` documents each append-only `findings.jsonl` record. Skills do not write this contract: they may emit `finding_candidate` claims in `skill_result` v1 only. A `validated_finding` is created only by the Python finding promotion workflow after human review, current scope evaluation, workflow-state checks, source-result validation, source-result SHA-256 recording, and local evidence integrity verification. The registry is separate from `findings.md`, which remains operator-managed Markdown until a later reporting/export task.

The browser can create guarded policy-checked skill_request v1 contracts and validate existing request/result contracts point-in-time. It does not execute contracts, create or upload skill results, execute recommendations, or promote findings.

## Web finding review

Skill-result contracts may contain `finding_candidate` claims. The web control plane inventories only metadata for those claims and promotes them only through explicit human review into the unchanged finding v1 schema. Request, result, and finding schemas are unchanged.
