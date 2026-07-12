# Evidence Preservation & Archiving

> Human-operator reference. Archiving tools, evidence handling workflows,
> and capture scripts. Extracted from skill files for clean separation.

---

## Archiving Platforms

- [archive.today](https://archive.today/) — one-page archiver + screenshot.
- [URLScan.io](https://urlscan.io/) — webpage scan + resource map.
- [ArchiveBox](https://archivebox.io/) — self-hosted (HTML, PDF, screenshots).
- Wayback SavePageNow API v3 — on-demand archiving with job IDs.
- [Hunchly](https://www.hunch.ly/) — investigator evidence capture (paid).
- [Kasm Workspaces](https://kasmweb.com/) — containerized OSINT browser isolation.
- [SingleFileZ](https://github.com/gildas-lormeau/SingleFileZ) — browser ext for offline HTML.

---

## Evidence Handling Discipline

URL + UTC timestamp + PNG + WARC/SingleFileZ archive, SHA-256 hash all downloads, separate work profiles per case, store evidence read-only, JSONL run logs with `run_id` + tool versions.

---

## Evidence Capture Script

```bash
mkdir -p evidence/$(date -u +%Y%m%d)
T="https://target.example"; P="/actuator/env"; TS=$(date -u +%Y%m%dT%H%M%SZ)
SAFE_NAME=$(echo "${T}${P}" | tr '/:' '_')
curl -sk -m 10 "$T$P" -o "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.body" \
  -D "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.headers"
sha256sum "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}".* > "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.sha256"
```

---
