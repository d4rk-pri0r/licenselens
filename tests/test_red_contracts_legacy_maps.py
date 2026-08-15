"""RED contract: centralized legacy check-ID maps must be gone (AF-A / T06 / T08)."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "src" / "licenselens" / "engine" / "_registry_check_map.py"
EVALUATORS_INIT = ROOT / "src" / "licenselens" / "evaluators" / "__init__.py"


def test_registry_check_map_module_must_not_exist() -> None:
    """``engine/_registry_check_map.py`` is a forbidden centralized switchboard."""
    assert not MAP_PATH.exists(), (
        "src/licenselens/engine/_registry_check_map.py must be removed; "
        "typed per-module registrations replace the centralized check-ID map (AF-A)"
    )


def test_evaluators_init_has_no_evaluators_switchboard() -> None:
    """``evaluators/__init__.py`` must not expose a large EVALUATORS dict switchboard."""
    source = EVALUATORS_INIT.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(EVALUATORS_INIT))

    assigned_names: set[str] = set()
    dict_sizes: dict[str, int] = {}

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned_names.add(target.id)
                    if isinstance(node.value, ast.Dict):
                        dict_sizes[target.id] = len(node.value.keys)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigned_names.add(node.target.id)
            if isinstance(node.value, ast.Dict):
                dict_sizes[node.target.id] = len(node.value.keys)

    assert "EVALUATORS" not in assigned_names, (
        "evaluators/__init__.py still defines EVALUATORS; "
        "registration switchboard must be removed (AF-A)"
    )
    # Belt-and-suspenders: no residual giant check-id dict of ~139 entries.
    oversized = {name: size for name, size in dict_sizes.items() if size >= 100}
    assert not oversized, (
        f"evaluators/__init__.py still contains oversized registration dicts: {oversized}"
    )


def test_evaluators_module_runtime_has_no_evaluators_mapping() -> None:
    """Import surface must not expose EVALUATORS after the switchboard is deleted."""
    import licenselens.evaluators as evaluators_mod

    mapping = getattr(evaluators_mod, "EVALUATORS", None)
    assert mapping is None, (
        f"licenselens.evaluators.EVALUATORS still present with {len(mapping)} entries; "
        "typed registry callables must replace the switchboard"
    )
