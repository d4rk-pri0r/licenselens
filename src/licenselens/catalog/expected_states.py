"""Deterministic ``check_id -> expected_state`` mapping for the report layer.

Importable without ``licenselens.evaluators`` or ``licenselens.collectors``:
it only reads the YAML check catalog through the engine loader.
"""

from __future__ import annotations

from licenselens.engine.loader import load_checks


def expected_state_map() -> dict[str, str]:
    """Return ``{check_id: expected_state}`` for every registered check.

    Built from the catalog sorted by check id, so the result is
    deterministic for equal catalogs.
    """
    checks = load_checks()
    return {check.id: check.expected_state for check in sorted(checks, key=lambda item: item.id)}
