from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

_PACKAGE = "outrider"
_SCHEMA_NAMES = {
    "skill-request-v1.schema.json",
    "skill-result-v1.schema.json",
    "finding-v1.schema.json",
}


def packaged_skill_catalog() -> tuple[str, ...]:
    """Return the immutable skill identifiers shipped with this Python package."""
    data = json.loads(resources.files(_PACKAGE).joinpath("skill_catalog.json").read_text(encoding="utf-8"))
    skills = data.get("skills", [])
    if not isinstance(skills, list) or not all(isinstance(item, str) for item in skills):
        raise RuntimeError("packaged skill catalog is malformed")
    return tuple(sorted(skills))


def schema_text(name: str) -> str:
    """Return a packaged JSON contract schema by filename."""
    if name not in _SCHEMA_NAMES:
        raise ValueError(f"unknown Outrider schema: {name}")
    return resources.files(_PACKAGE).joinpath("schemas", name).read_text(encoding="utf-8")


def schema_json(name: str) -> dict[str, Any]:
    """Return a packaged JSON contract schema parsed as a dictionary."""
    data = json.loads(schema_text(name))
    if not isinstance(data, dict):
        raise RuntimeError(f"packaged schema is not a JSON object: {name}")
    return data


def web_static_path(name: str) -> Path:
    """Return a packaged web static resource path for local read-only serving."""
    if name not in {"index.html", "app.css", "app.js"}:
        raise ValueError(f"unknown Outrider web static resource: {name}")
    return Path(str(resources.files(_PACKAGE).joinpath("web_static", name)))
