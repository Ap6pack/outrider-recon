#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.local/share/outrider-recon"
SKILLS_DIR="$HOME/.claude/skills"

echo "Uninstalling outrider-recon..."

# Remove only symlinks that resolve into our install directory. Matching on the
# link target rather than a hardcoded name list keeps this correct as skills are
# added or renamed, and avoids deleting a user's own skill that happens to share
# a generic name such as "report-template".
removed=0
if [ -d "$SKILLS_DIR" ]; then
  for target in "$SKILLS_DIR"/*; do
    [ -L "$target" ] || continue
    dest="$(readlink "$target")"
    case "$dest" in
      "$INSTALL_DIR" | "$INSTALL_DIR"/*)
        rm -f "$target"
        echo "  Removed: $(basename "$target")"
        removed=$((removed + 1))
        ;;
    esac
  done
fi

if [ -d "$INSTALL_DIR" ]; then
  rm -rf "$INSTALL_DIR"
  echo "  Removed: $INSTALL_DIR"
fi

echo "Done! outrider-recon has been uninstalled ($removed skill links removed)."
