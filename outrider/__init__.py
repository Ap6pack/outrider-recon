"""Outrider Recon CLI harness."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("outrider-recon")
except PackageNotFoundError:  # pragma: no cover - source tree fallback
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    __version__ = next(line.split("=", 1)[1].strip().strip("\"'") for line in pyproject.read_text(encoding="utf-8").splitlines() if line.strip().startswith("version ="))
