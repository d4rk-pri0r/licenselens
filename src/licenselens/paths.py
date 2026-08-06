"""Resolve packaged data directories (catalog, checks, templates)."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def _repo_root() -> Path | None:
    """Return repo root when running from a source checkout."""
    here = Path(__file__).resolve()
    # src/licenselens/paths.py -> repo root is parents[2]
    candidate = here.parents[2]
    if (candidate / "catalog").is_dir() and (candidate / "checks").is_dir():
        return candidate
    return None


def catalog_dir() -> Path:
    root = _repo_root()
    if root is not None:
        return root / "catalog"
    return Path(str(resources.files("licenselens") / "data" / "catalog"))


def checks_dir() -> Path:
    root = _repo_root()
    if root is not None:
        return root / "checks"
    return Path(str(resources.files("licenselens") / "data" / "checks"))


def templates_dir() -> Path:
    root = _repo_root()
    if root is not None:
        return root / "templates"
    return Path(str(resources.files("licenselens") / "data" / "templates"))
