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

```
What ports should I probe to find Swagger or OpenAPI specs on a webapp?
```

Claude should pull the Swagger wordlist from the `web-surface` skill. If it doesn't, see [troubleshooting](#troubleshooting) below.

## Claude.ai (Pro / Team / Enterprise)

1. Open https://claude.ai
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
3. In a fresh session, ask: *"Do you have access to a skill named offensive-osint?"* — Claude should confirm.
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

## Verifying skill version

All SKILL.md files declare `version:` in the YAML frontmatter. Current project release: v2.3. Individual skill versions in YAML frontmatter. Check via:

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
