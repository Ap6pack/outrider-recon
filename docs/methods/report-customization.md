# Report Customization Guide

> Human-operator reference. Adapting outrider-recon report templates
> to client-specific formats and branding requirements.

---

## 1. Template Variables

The report-template skill uses standard placeholders that get replaced at
render time. Every engagement must define these before generating output:

| Variable                | Description                          | Example                        |
|-------------------------|--------------------------------------|--------------------------------|
| `{client_name}`         | Legal entity name of the client      | Acme Corp                      |
| `{engagement_date}`     | Start date of the engagement         | 2026-05-29                     |
| `{assessor}`            | Name or handle of the lead assessor  | J. Smith                       |
| `{scope}`               | Agreed-upon scope summary            | *.acme.com, 198.51.100.0/24   |
| `{methodology_version}` | Version of the methodology applied  | outrider-recon v2.4            |

**Setting variables per engagement:**

1. Create a `.report-config.json` in the engagement directory (see Section 5).
2. Or pass them inline when invoking the report-template skill:
   ```
   /report-template --client_name "Acme Corp" --engagement_date 2026-05-29 \
                    --assessor "J. Smith" --scope "*.acme.com" \
                    --methodology_version "outrider-recon v2.4"
   ```
3. Variables not set fall back to `[UNSET]` so they are visible in review.

---

## 2. Format Adaptation

### Section Mapping

| report-template section       | Big-4 equiv              | Boutique equiv          | Bug bounty equiv         |
|-------------------------------|--------------------------|-------------------------|--------------------------|
| Executive Summary             | Management Summary       | Executive Overview      | Summary                  |
| Scope & Methodology           | Engagement Scope         | Approach                | Scope                    |
| Asset Discovery Findings      | External Footprint       | Attack Surface Map      | Subdomains / Assets      |
| Vulnerability Detail          | Detailed Findings        | Technical Findings      | Vulnerability Report     |
| Risk Rating Matrix            | Risk Assessment          | Risk Ranking            | Severity Table           |
| Remediation Roadmap           | Recommendations          | Remediation Plan        | Fix Suggestions          |
| Appendices (raw data, logs)   | Supporting Evidence      | Technical Appendix      | Proof of Concept         |

### Executive Summary Customization

- **Tone:** Match the audience. Board-level readers need business impact language,
  not CVE numbers. Technical leads want specifics.
- **Length:** 1 paragraph for bug bounty, 0.5-1 page for boutique, 1-2 pages for
  Big-4 style reports.
- **Audience guidance:** State who the intended reader is at the top of the summary
  so reviewers can calibrate language before sign-off.

### Technical Detail Verbosity

| Level           | When to use                        | What it includes                                  |
|-----------------|------------------------------------|---------------------------------------------------|
| Minimal         | Bug bounty, triage reports         | Title, severity, affected asset, one-liner proof  |
| Standard        | Boutique consulting, most clients  | Full description, evidence, remediation steps     |
| Comprehensive   | Big-4, regulated industries        | All of standard plus risk context, references,    |
|                 |                                    | compliance mapping, and step-by-step reproduction |

---

## 3. Branding

### Header / Footer Insertion Points

- **Header:** Replace the `<!-- HEADER_SLOT -->` comment in the template with
  client-specific header HTML or markdown. Appears on every page in PDF output.
- **Footer:** Replace `<!-- FOOTER_SLOT -->` with confidentiality notice, page
  numbers, or client boilerplate.

### Logo Placement

- Place the client logo file in the engagement directory as `logo.png` or
  reference an absolute path in `.report-config.json` under `logo_path`.
- The template inserts the logo at the top-left of page 1 and optionally in
  the header of subsequent pages.
- Recommended size: 200x60px PNG with transparent background.

### Color Scheme

Keep severity colors consistent across all deliverables to avoid confusion:

| Severity  | Color   | Hex       |
|-----------|---------|-----------|
| Critical  | Red     | `#E74C3C` |
| High      | Orange  | `#E67E22` |
| Medium    | Yellow  | `#F1C40F` |
| Low       | Green   | `#27AE60` |
| Info      | Gray    | `#95A5A6` |

Client branding colors apply to headings, borders, and accent elements only.
Never override severity colors with brand colors.

---

## 4. Delivery Formats

### Markdown to PDF (pandoc + custom CSS)

```bash
pandoc report.md -o report.pdf \
  --pdf-engine=wkhtmltopdf \
  --css=client-style.css \
  --metadata title="Security Assessment - {client_name}" \
  --variable margin-top=25mm \
  --variable margin-bottom=25mm
```

### Markdown to DOCX (pandoc + reference doc)

```bash
pandoc report.md -o report.docx \
  --reference-doc=client-template.docx
```

Place `client-template.docx` in the engagement directory. It carries the
client's heading styles, fonts, header/footer, and page layout.

### Markdown to HTML (web portal delivery)

```bash
pandoc report.md -o report.html \
  --standalone \
  --css=client-style.css \
  --metadata title="Security Assessment - {client_name}" \
  --toc --toc-depth=3
```

Add `--self-contained` to embed images and CSS into a single HTML file for
easy upload to client portals.

---

## 5. Per-Client Config File

Create `.report-config.json` in the engagement root directory:

```json
{
  "client_name": "Acme Corp",
  "logo_path": "./logo.png",
  "template_variant": "standard",
  "severity_labels": {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational"
  },
  "custom_header": "CONFIDENTIAL - Acme Corp Internal Use Only",
  "custom_footer": "Copyright 2026 Acme Corp. Prepared by Outrider Recon."
}
```

**Schema fields:**

| Field              | Type   | Required | Description                                       |
|--------------------|--------|----------|---------------------------------------------------|
| `client_name`      | string | yes      | Used in all template variable substitutions        |
| `logo_path`        | string | no       | Relative or absolute path to client logo           |
| `template_variant` | string | no       | One of: minimal, standard, comprehensive           |
| `severity_labels`  | object | no       | Override default severity display names             |
| `custom_header`    | string | no       | Text or HTML inserted in the header slot           |
| `custom_footer`    | string | no       | Text or HTML inserted in the footer slot           |

**How the report-template skill reads this config:**

1. On invocation, the skill looks for `.report-config.json` in the current
   working directory, then walks up to the engagement root.
2. Values from the config file populate template variables automatically.
3. Inline flags override config file values when both are present.
4. Missing optional fields fall back to built-in defaults.
