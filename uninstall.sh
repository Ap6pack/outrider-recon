#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.local/share/outrider-recon"
SKILLS_DIR="$HOME/.claude/skills"
SKILLS=(osint-methodology offensive-osint recon-asset-discovery web-surface identity-fabric secrets-and-dorks post-discovery cloud-and-infra people-breach-intel analysis-and-reporting report-template)

echo "Uninstalling outrider-recon..."

for skill in "${SKILLS[@]}"; do
  target="$SKILLS_DIR/$skill"
  if [ -L "$target" ] || [ -d "$target" ]; then
    rm -rf "$target"
    echo "  Removed: $skill"
  fi
done

if [ -d "$INSTALL_DIR" ]; then
  rm -rf "$INSTALL_DIR"
  echo "  Removed: $INSTALL_DIR"
fi

echo "Done! outrider-recon has been uninstalled."
