#!/usr/bin/env bash
set -euo pipefail

# outrider-recon one-command setup + self-check.
#
# Run from a checkout of the repo:
#   ./bootstrap.sh                # venv + web extra + link skills + self-check
#   ./bootstrap.sh --no-web       # base install only (no FastAPI/uvicorn)
#   ./bootstrap.sh --no-skills    # skip linking Claude skills into ~/.claude/skills
#   ./bootstrap.sh --help
#
# It creates an isolated virtualenv in ./.venv, installs the Python package,
# symlinks the 11 Claude skills from THIS checkout into ~/.claude/skills, and
# runs the deterministic benchmark self-check (no model, no network) so you know
# the install works before you touch a real target.

WEB=1
SKILLS=1
VENV_DIR=".venv"
SKILLS_DIR="${HOME}/.claude/skills"

usage() {
  cat <<'USAGE'
outrider-recon one-command setup + self-check. Run from a repo checkout.

Usage: ./bootstrap.sh [options]
  (no options)   virtualenv + web extra + link skills + self-check
  --no-web       base install only (no FastAPI/uvicorn)
  --no-skills    skip linking Claude skills into ~/.claude/skills
  -h, --help     show this help

Creates an isolated virtualenv in ./.venv, installs the package, symlinks the
Claude skills from THIS checkout into ~/.claude/skills, and runs the
deterministic benchmark self-check (no model, no network).
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-web) WEB=0 ;;
    --no-skills) SKILLS=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Error: unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

if [ ! -f "pyproject.toml" ]; then
  echo "Error: run bootstrap.sh from inside the outrider-recon checkout." >&2
  exit 1
fi

# 1. Find a Python interpreter >= 3.10.
find_python() {
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)' 2>/dev/null; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

if ! PY="$(find_python)"; then
  echo "Error: Python 3.10+ is required but was not found on PATH." >&2
  exit 1
fi
echo "Using $("$PY" --version 2>&1) at $(command -v "$PY")"

# 2. Create the isolated virtualenv.
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtualenv in $VENV_DIR ..."
  "$PY" -m venv "$VENV_DIR"
fi
VPY="$VENV_DIR/bin/python"
if [ ! -x "$VPY" ]; then
  VPY="$VENV_DIR/Scripts/python.exe"  # Windows layout fallback
fi
if [ ! -x "$VPY" ]; then
  echo "Error: virtualenv Python not found under $VENV_DIR." >&2
  exit 1
fi

# 3. Install the package.
"$VPY" -m pip install --quiet --upgrade pip
if [ "$WEB" -eq 1 ]; then
  echo "Installing outrider-recon with the web extra ..."
  "$VPY" -m pip install --quiet -e ".[web]"
else
  echo "Installing outrider-recon (base) ..."
  "$VPY" -m pip install --quiet -e .
fi

# 4. Link the Claude skills from THIS checkout (no re-clone).
if [ "$SKILLS" -eq 1 ]; then
  mkdir -p "$SKILLS_DIR"
  linked=0
  for skill_dir in "$REPO_DIR"/skills/*/; do
    [ -f "${skill_dir}SKILL.md" ] || continue
    skill_dir="${skill_dir%/}"
    target="$SKILLS_DIR/$(basename "$skill_dir")"
    if [ -L "$target" ] || [ -e "$target" ]; then
      rm -rf "$target"
    fi
    ln -sfn "$skill_dir" "$target"
    linked=$((linked + 1))
  done
  echo "Linked $linked Claude skills into $SKILLS_DIR"
fi

# 5. Deterministic self-check: no model, no network.
echo ""
echo "Running self-check (deterministic benchmark) ..."
"$VPY" -m outrider benchmark run --tally-only

# 6. Next steps.
cat <<EOF

Setup complete. Activate the environment with:
  source $VENV_DIR/bin/activate

Then pick how you want to use Outrider:
  * Web portal (human UI):     outrider
  * Governed-loop status:      outrider orchestrate status runs/<target>
  * Full test suite:           python -m unittest discover -s tests -p "test_*.py"
  * Claude skills:             start a Claude Code session and ask for an
                               authorized external recon plan.

Use Outrider only for assets you own or are authorized to assess.
EOF
