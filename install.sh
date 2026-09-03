#!/usr/bin/env bash
set -euo pipefail

# outrider-recon installer for Claude Code
# Usage: curl -fsSL https://raw.githubusercontent.com/Ap6pack/outrider-recon/main/install.sh | bash

REPO="https://github.com/Ap6pack/outrider-recon.git"
INSTALL_DIR="$HOME/.local/share/outrider-recon"
SKILLS_DIR="$HOME/.claude/skills"

echo "Installing outrider-recon..."

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is required but was not found on PATH." >&2
  exit 1
fi

# Clone or update
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing installation..."
  git -C "$INSTALL_DIR" pull --quiet
elif [ -e "$INSTALL_DIR" ]; then
  echo "Error: $INSTALL_DIR already exists but is not a git checkout." >&2
  echo "Move or remove it, then re-run this installer." >&2
  exit 1
else
  echo "Cloning repository..."
  git clone --quiet "$REPO" "$INSTALL_DIR"
fi

# Create skills directory if needed
mkdir -p "$SKILLS_DIR"

# Symlink each skill. The symlink exposes the entire skill directory, including
# offensive-osint/scripts/, so helper scripts need no separate copy step.
skill_count=0
for skill_dir in "$INSTALL_DIR"/skills/*/; do
  [ -f "$skill_dir/SKILL.md" ] || continue
  skill_dir="${skill_dir%/}"
  skill_name="$(basename "$skill_dir")"
  target="$SKILLS_DIR/$skill_name"
  if [ -L "$target" ] || [ -e "$target" ]; then
    rm -rf "$target"
  fi
  ln -sfn "$skill_dir" "$target"
  skill_count=$((skill_count + 1))
  echo "  Linked: $skill_name"
done

echo ""
echo "Done! $skill_count skills installed."
echo "Start a new Claude Code session and try:"
echo "  'Plan a 4-hour external recon on acme.com (in-scope bug bounty)'"
echo ""
echo "To update later: git -C $INSTALL_DIR pull"
echo "To uninstall:    $INSTALL_DIR/uninstall.sh"
