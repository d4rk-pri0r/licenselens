"""Reusable WCAG 2.x contrast helpers for design-contract tests.

Pure, dependency-free functions: parse ``#rrggbb`` strings, compute relative
luminance per the WCAG 2.x formula, and return the contrast ratio between two
colors. Importable from anywhere in the test suite via ``tests.wcag``.
"""

from __future__ import annotations

import pytest

_HEX_RE = r"^#[0-9a-fA-F]{6}$"


def _parse_hex(color: str) -> tuple[int, int, int]:
    import re

    if not re.fullmatch(_HEX_RE, color):
        raise ValueError(f"expected #rrggbb hex color, got {color!r}")
    value = color[1:]
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def relative_luminance(rgb: tuple[int, int, int]) -> float:
    """Relative luminance of an 8-bit RGB triple per WCAG 2.x (0.0..1.0)."""

    def channel(value: int) -> float:
        normalized = value / 255.0
        if normalized <= 0.03928:
            return normalized / 12.92
        return ((normalized + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast_ratio(fg: str, bg: str) -> float:
    """WCAG 2.x contrast ratio between two ``#rrggbb`` colors (1.0..21.0)."""
    fg_luminance = relative_luminance(_parse_hex(fg))
    bg_luminance = relative_luminance(_parse_hex(bg))
    lighter, darker = (
        (fg_luminance, bg_luminance)
        if fg_luminance >= bg_luminance
        else (bg_luminance, fg_luminance)
    )
    return (lighter + 0.05) / (darker + 0.05)


SEMANTIC_PRINT_COLORS = ("#ff737a", "#e2b84b", "#67c991", "#96938b")


def test_contrast_ratio_canonical_extremes() -> None:
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0, abs=1e-9)
    assert contrast_ratio("#ffffff", "#000000") == pytest.approx(21.0, abs=1e-9)
    assert contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0, abs=1e-9)


def test_contrast_ratio_rejects_malformed_input() -> None:
    for bad in ("", "#fff", "fff", "#12345", "#gggggg", "#1234567", "red"):
        with pytest.raises(ValueError, match="expected #rrggbb"):
            contrast_ratio(bad, "#ffffff")


def test_cool_blue_accent_on_canvas() -> None:
    assert contrast_ratio("#88b4d8", "#0f1114") >= 4.5


def test_cool_blue_focus_on_surface() -> None:
    assert contrast_ratio("#b8d6ee", "#16191d") >= 3.0


def test_print_accent_on_white() -> None:
    assert contrast_ratio("#2c5a7d", "#ffffff") >= 4.5


def test_screen_semantic_colors_on_white_are_not_print_safe() -> None:
    """Screen semantic tokens are not used as print inks; pin that they stay
    below AA on white so print overrides remain required."""
    recorded = {
        "#ff737a": 2.6298,
        "#e2b84b": 1.8764,
        "#67c991": 2.0309,
        "#96938b": 3.0688,
    }
    for color, expected in recorded.items():
        ratio = contrast_ratio(color, "#ffffff")
        assert ratio == pytest.approx(expected, abs=1e-4), f"recorded ratio for {color} drifted"
        assert ratio < 4.5, f"screen semantic {color} unexpectedly print-safe on white"


def test_print_status_inks_meet_aa_on_white() -> None:
    for color in ("#b3261e", "#8a5a00", "#1e7a3a", "#57534e"):
        assert contrast_ratio(color, "#ffffff") >= 4.5, f"print ink {color} below 4.5:1 on white"
