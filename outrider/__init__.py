"""Outrider Recon CLI harness."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib

try:
    __version__ = version("outrider-recon")
except PackageNotFoundError:  # pragma: no cover - source tree fallback
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    __version__ = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
