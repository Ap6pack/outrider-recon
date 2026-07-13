#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PYTHON_VERSION = "0.2.0"
PLUGIN_VERSION = "3.0.1"
BUNDLE = "outrider-recon"
ARCHIVE_NAME = f"{BUNDLE}-bundle-{PLUGIN_VERSION}.zip"
ROOT_DIR = f"{BUNDLE}-bundle-{PLUGIN_VERSION}"
ALLOWLIST_FILES = [
    ".claude-plugin/plugin.json", ".mcp.json", ".gitignore", "pyproject.toml", "README.md", "CHANGELOG.md",
    "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CLAUDE.md.example", "install.sh", "uninstall.sh",
    "tools/release_audit.py", "tools/build_release_bundle.py",
]
ALLOWLIST_DIRS = ["outrider", "contracts", "skills", "mcp-server", "docs", "examples"]
EXCLUDED_NAMES = {".git", ".github", "tests", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "artifacts", "runs"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".log")
EXCLUDED_EXACT = {"evidence.jsonl", "approvals.jsonl", "findings.jsonl", "manifest.json", ".env"}
SCHEMA_VERSIONS = {"manifest": 1, "state_event": 1, "evidence": 1, "approval": 1, "skill_request": 1, "skill_result": 1, "finding": 1}

class BundleError(Exception):
    pass

def read_py_version() -> str:
    import tomllib
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]

def skill_names() -> list[str]:
    return sorted(p.parent.name for p in (ROOT / "skills").glob("*/SKILL.md") if p.parent.name != "_shared")

def validate_versions() -> list[str]:
    py = read_py_version()
    plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
    if py != PYTHON_VERSION or plugin != PLUGIN_VERSION or py == plugin:
        raise BundleError(f"version mismatch: python={py!r} plugin={plugin!r}")
    skills = skill_names()
    if len(skills) != 11:
        raise BundleError(f"expected 11 skills, found {len(skills)}")
    for schema in ["skill-request-v1.schema.json", "skill-result-v1.schema.json", "finding-v1.schema.json"]:
        data = json.loads((ROOT / "contracts" / schema).read_text())
        if data.get("properties", {}).get("schema_version", {}).get("const") != 1:
            raise BundleError(f"schema version changed: {schema}")
    return skills

def is_excluded(rel: Path) -> bool:
    parts = rel.parts
    if len(parts) >= 2 and parts[0] == "examples" and parts[1] == "run-folder":
        return True
    if any(part in EXCLUDED_NAMES for part in parts):
        return True
    if rel.name.endswith(".egg-info") or rel.name in EXCLUDED_EXACT or rel.suffix in EXCLUDED_SUFFIXES:
        return True
    if rel.name.startswith(".env") or rel.name in {".DS_Store"}:
        return True
    return False

def assert_safe(rel: Path, path: Path) -> None:
    if path.is_symlink():
        raise BundleError(f"unexpected symlink: {rel.as_posix()}")
    posix = rel.as_posix()
    pure = PurePosixPath(posix)
    if posix.startswith("/") or ".." in pure.parts:
        raise BundleError(f"unsafe path: {posix}")
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise BundleError(f"path escapes repository: {posix}") from exc

def collect_files() -> list[Path]:
    files: set[Path] = set()
    for name in ALLOWLIST_FILES:
        p = ROOT / name
        if not p.is_file():
            raise BundleError(f"missing release input: {name}")
        files.add(Path(name))
    for dirname in ALLOWLIST_DIRS:
        base = ROOT / dirname
        if not base.is_dir():
            raise BundleError(f"missing release input: {dirname}")
        for p in base.rglob("*"):
            rel = p.relative_to(ROOT)
            if is_excluded(rel):
                continue
            assert_safe(rel, p)
            if p.is_file():
                files.add(rel)
            elif p.is_symlink():
                raise BundleError(f"unexpected symlink: {rel.as_posix()}")
    return sorted(files, key=lambda x: x.as_posix())

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def zip_info(name: str, epoch: int, mode: int = 0o644) -> zipfile.ZipInfo:
    z = zipfile.ZipInfo(name, dt.datetime.fromtimestamp(epoch, dt.timezone.utc).timetuple()[:6])
    z.compress_type = zipfile.ZIP_DEFLATED
    z.external_attr = (stat.S_IFREG | mode) << 16
    return z

def build(output_dir: Path, epoch: int, force: bool) -> dict[str, object]:
    skills = validate_versions()
    files = collect_files()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / ARCHIVE_NAME
    if archive.exists():
        if not force:
            raise BundleError(f"output already exists: {archive}")
        archive.unlink()
    manifest_files = []
    for rel in files:
        p = ROOT / rel
        manifest_files.append({"path": rel.as_posix(), "sha256": digest(p), "size_bytes": p.stat().st_size})
    manifest = {
        "schema_version": 1,
        "bundle": BUNDLE,
        "plugin_version": PLUGIN_VERSION,
        "python_version": PYTHON_VERSION,
        "generated_at": dt.datetime.fromtimestamp(epoch, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "skill_count": len(skills),
        "skills": skills,
        "schema_versions": SCHEMA_VERSIONS,
        "files": manifest_files,
    }
    with zipfile.ZipFile(archive, "w") as zf:
        for rel in files:
            mode = 0o755 if rel.name in {"install.sh", "uninstall.sh", "build_release_bundle.py", "release_audit.py"} else 0o644
            zf.writestr(zip_info(f"{ROOT_DIR}/{rel.as_posix()}", epoch, mode), (ROOT / rel).read_bytes())
        zf.writestr(zip_info(f"{ROOT_DIR}/RELEASE-MANIFEST.json", epoch), json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    return {"python_version": PYTHON_VERSION, "plugin_version": PLUGIN_VERSION, "skill_count": len(skills), "file_count": len(files), "bundle_filename": archive.name, "bundle_sha256": digest(archive), "bundle_size": archive.stat().st_size, "bundle_path": str(archive)}

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", default="dist")
    ap.add_argument("--source-date-epoch", type=int, default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    epoch = args.source_date_epoch if args.source_date_epoch is not None else int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    try:
        result = build(Path(args.output_dir), epoch, args.force)
    except Exception as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Python version: {result['python_version']}")
        print(f"Plugin/content version: {result['plugin_version']}")
        print(f"Skill count: {result['skill_count']}")
        print(f"File count: {result['file_count']}")
        print(f"Bundle filename: {result['bundle_filename']}")
        print(f"Bundle SHA-256: {result['bundle_sha256']}")
        print(f"Bundle size: {result['bundle_size']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
