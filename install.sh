#!/usr/bin/env bash
set -euo pipefail

# outrider-recon installer for Claude Code
# Usage: curl -fsSL https://raw.githubusercontent.com/Ap6pack/outrider-recon/main/install.sh | bash

REPO="https://github.com/Ap6pack/outrider-recon.git"
INSTALL_DIR="$HOME/.local/share/outrider-recon"
SKILLS_DIR="$HOME/.claude/skills"

echo "Installing outrider-recon..."

# Clone or update
if [ -d "$INSTALL_DIR" ]; then
  echo "Updating existing installation..."
  git -C "$INSTALL_DIR" pull --quiet
else
  echo "Cloning repository..."
  git clone --quiet "$REPO" "$INSTALL_DIR"
fi

# Create skills directory if needed
mkdir -p "$SKILLS_DIR"

# Symlink each skill
for skill_dir in "$INSTALL_DIR"/skills/*/; do
  skill_name=$(basename "$skill_dir")
  target="$SKILLS_DIR/$skill_name"
  if [ -L "$target" ] || [ -d "$target" ]; then
    rm -rf "$target"
  fi
  ln -sf "$skill_dir" "$target"
  echo "  Linked: $skill_name"
done

# Copy helper scripts
if [ -d "$INSTALL_DIR/skills/offensive-osint/scripts" ]; then
  mkdir -p "$SKILLS_DIR/offensive-osint/scripts"
  cp "$INSTALL_DIR/skills/offensive-osint/scripts/"*.py "$SKILLS_DIR/offensive-osint/scripts/" 2>/dev/null || true
fi

SKILL_COUNT=$(ls -d "$SKILLS_DIR"/*/SKILL.md 2>/dev/null | wc -l)
echo ""
echo "Done! $SKILL_COUNT skills installed."
echo "Start a new Claude Code session and try:"
echo "  'Plan a 4-hour external recon on acme.com (in-scope bug bounty)'"
echo ""
echo "To update later: git -C $INSTALL_DIR pull"
echo "To uninstall:    rm -rf $INSTALL_DIR && rm -rf $SKILLS_DIR/{osint-methodology,offensive-osint,recon-asset-discovery,web-surface,identity-fabric,secrets-and-dorks,post-discovery,cloud-and-infra,people-breach-intel,analysis-and-reporting,report-template}"
