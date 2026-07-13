# Installation

These skills are plain Markdown files. Installing them depends on which Claude surface you're using.

## One-Click Install (Recommended)

Run the install script:

```bash
curl -fsSL https://raw.githubusercontent.com/Ap6pack/outrider-recon/main/install.sh | bash
```

This clones the repo to `~/.local/share/outrider-recon` and symlinks all 11 skills into `~/.claude/skills/`. To update later, just re-run the same command.

### Optional: MCP Server

The project includes an optional MCP server that adds live API tools (crt.sh lookup, HudsonRock query, EPSS scoring, Wayback CDX, DNS records). To enable it:

1. Install dependencies: `pip install -r mcp-server/requirements.txt`
2. The `.mcp.json` config is already included in the repo

The MCP server is optional -- all skills work without it.

## Python package installation

The Python package version is `0.2.0` and is independent of the Claude plugin/content version `3.0.1`.

### Install from the published GitHub release wheel

1. Open the Python 0.2.0 GitHub release page: <https://github.com/Ap6pack/outrider-recon/releases/tag/python-v0.2.0>.
2. Download `outrider_recon-0.2.0-py3-none-any.whl` into an artifact directory.
3. Install the downloaded base wheel:

```bash
python -m pip install ./outrider_recon-0.2.0-py3-none-any.whl
```

4. To install optional local web review dependencies from the downloaded wheel, run:

```bash
python -m pip install "./outrider_recon-0.2.0-py3-none-any.whl[web]"
```

5. Verify the installed version:

```bash
outrider --version
python -m outrider --version
```

The release documentation does not claim PyPI publication for `outrider-recon==0.2.0`.

### Install from a source checkout

From a repository checkout, install the base CLI with:

```bash
python -m pip install .
```

The base installation provides deterministic local run, scope, state, evidence, approval, action-policy, contract, finding, and review controls. It does not install FastAPI, Uvicorn, httpx, or the MCP SDK, and it does not execute the recon methodology itself. To install the optional local read-only web review plane from a source checkout, use:

```bash
python -m pip install ".[web]"
```

### Optional MCP server from source checkout

The optional MCP server calls the Python control layer and enforces run context, scope, state, and approval policy before the existing live enrichment operations. Denied MCP decisions perform no HTTP or DNS request. Install its dependencies separately from a source checkout:

```bash
python -m pip install -r mcp-server/requirements.txt
```

Re-running `install.sh` updates the Claude skill symlinks from the current repository content. The `_shared` directory is support material and is not installed as a twelfth skill.

### Plugin/content release bundle

Open the plugin/content 3.0.1 GitHub release page: <https://github.com/Ap6pack/outrider-recon/releases/tag/plugin-v3.0.1>. Download `outrider-recon-bundle-3.0.1.zip`, verify the relevant checksum entry, extract it into a review directory, inspect `RELEASE-MANIFEST.json`, and then follow the Claude skill installation method for your Claude surface. No Claude Marketplace publication is claimed.

If only the plugin bundle is present in your artifact directory, verify just that checksum entry:

```bash
grep 'outrider-recon-bundle-3.0.1.zip' SHA256SUMS | sha256sum -c -
```

If only the Python artifacts are present, verify just the Python entries:

```bash
grep -E 'outrider_recon-0.2.0-py3-none-any.whl|outrider_recon-0.2.0.tar.gz' SHA256SUMS | sha256sum -c -
```

An unfiltered `sha256sum -c SHA256SUMS` expects every artifact named in the shared checksum file to exist in the current artifact directory.

## Claude Code (CLI)

Claude Code looks for skills in `~/.claude/skills/` by default.

### Method 1: Direct copy

```bash
git clone https://github.com/Ap6pack/outrider-recon.git
cd outrider-recon

# Copy all skills into your local Claude Code skills directory
mkdir -p ~/.claude/skills
cp -r skills/* ~/.claude/skills/
```

### Method 2: Symlink (stays in sync with git pull)

```bash
git clone https://github.com/Ap6pack/outrider-recon.git ~/.local/share/outrider-recon
mkdir -p ~/.claude/skills

# Symlink each skill directory
for skill in ~/.local/share/outrider-recon/skills/*/; do
  ln -sf "$skill" ~/.claude/skills/
done
```

Then `git -C ~/.local/share/outrider-recon pull` periodically to stay current.

### Verify install

Start a new Claude Code session and type:

```text
What ports should I probe to find Swagger or OpenAPI specs on a webapp?
```

Claude should pull the Swagger wordlist from the `web-surface` skill. If it doesn't, see [troubleshooting](#troubleshooting) below.

## Claude.ai (Pro / Team / Enterprise)

1. Open <https://claude.ai>
2. Create a new Project (or open an existing one).
3. Click **Add knowledge** → **Files**.
4. Upload the router skill (`skills/offensive-osint/SKILL.md`) and the methodology skill (`skills/osint-methodology/SKILL.md`) at minimum. For full coverage, upload all 11 `skills/*/SKILL.md` files.
5. (Optional) Also upload `tests/smoke-test-prompts.md` for self-test reference.
6. Save.

In any conversation within that Project, the skills are available as system knowledge.

## Claude API (Anthropic SDK)

Attach the skill content as part of the system prompt. At minimum, include the router and methodology; for full coverage, load all 11 skills:

```python
from anthropic import Anthropic
from pathlib import Path

client = Anthropic()

# Load all skill files (~3,000 lines total)
skills_dir = Path("skills")
skill_blocks = []
for skill_path in sorted(skills_dir.glob("*/SKILL.md")):
    skill_name = skill_path.parent.name
    content = skill_path.read_text()
    skill_blocks.append(f"=== SKILL: {skill_name} ===\n{content}")

all_skills = "\n\n".join(skill_blocks)

system_prompt = f"""You are an OSINT recon assistant for authorized red-team engagements.
You have access to the following skills that you should reference whenever relevant:

{all_skills}
"""

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=4096,
    system=system_prompt,
    messages=[{"role": "user", "content": "Plan a 4-hour external recon on acme.com (in-scope BB)"}]
)
print(response.content[0].text)
```

## Claude Agent SDK / Cowork mode

These platforms typically auto-discover skills in `~/.claude/skills/`. Install via the Claude Code method above and they'll be available.

If you're building a custom agent with the SDK, attach SKILL.md content to your agent's system prompt as shown in the API method.

## Cursor / other AI IDEs

Most AI IDEs allow custom system-prompt injection. Use the API method above as a template.

## Troubleshooting

### "Claude doesn't seem to know about the skill"

1. Verify the file is at `~/.claude/skills/<skill-name>/SKILL.md` (not `~/.claude/skills/<skill-name>.md`).
2. Restart Claude Code.
3. In a fresh session, ask: _"Do you have access to a skill named offensive-osint?"_ — Claude should confirm.
4. Check the YAML frontmatter is intact (begins with `---` and ends with `---`).

### "The skill loads but doesn't trigger on my prompt"

The skill's `triggers:` list controls auto-activation. If your prompt's wording isn't in the list, Claude may not pull the skill.

- Try rephrasing with a phrase from the SKILL.md `triggers:` list.
- If your phrasing is a common practitioner term, [open an issue](https://github.com/Ap6pack/outrider-recon/issues) to add it.

### "Skill is too large for my model's context"

All 11 skills together are ~3,000 lines. This fits comfortably in modern Claude context windows (200K+). If you're using an older model with smaller context:

- Attach only the router (`offensive-osint`) + methodology (`osint-methodology`) for core functionality.
- Or attach only the sub-skills relevant to the task.
- Or run a model with larger context (Claude Sonnet 4.6+, Opus 4.6+).

### "I want to filter the skill content"

Edit `skills/<skill-name>/SKILL.md` directly. All files are plain Markdown. You can comment out sections you don't need or split them into multiple smaller skills.

## Installing skills vs. the Python CLI

The Claude skill/plugin bundle and the Python CLI package are separate installation concerns:

- The one-click and manual Claude Code flows install the skill bundle into `~/.claude/skills/` so Claude can load the methodology and sub-skills.
- The Python package exposes the `outrider` console script for deterministic local run, scope, state, evidence, approval, action-policy, contract, finding, and review controls. It does not execute the recon methodology itself.
- The optional MCP server is installed separately from `mcp-server/requirements.txt` and adds live enrichment tools. It calls the Python control layer before live operations and denied decisions perform no HTTP or DNS request.

## Verifying versions

Version numbers are tracked by domain rather than forced to match:

- Plugin/content release: see `CHANGELOG.md` and `.claude-plugin/plugin.json`.
- Python CLI package: see `pyproject.toml` and `outrider/__init__.py`.
- Individual skills: see each SKILL.md YAML frontmatter.
- MCP implementation: see `mcp-server/` source and dependencies.

Check individual skill versions with:

```bash
grep "^version:" skills/*/SKILL.md
```

## Uninstalling

```bash
rm -rf ~/.claude/skills/analysis-and-reporting \
       ~/.claude/skills/cloud-and-infra \
       ~/.claude/skills/identity-fabric \
       ~/.claude/skills/offensive-osint \
       ~/.claude/skills/osint-methodology \
       ~/.claude/skills/people-breach-intel \
       ~/.claude/skills/post-discovery \
       ~/.claude/skills/recon-asset-discovery \
       ~/.claude/skills/report-template \
       ~/.claude/skills/secrets-and-dorks \
       ~/.claude/skills/web-surface
```

Or remove the symlinks if you used method 2 above.
