"""Pack pinned Microsoft workload icons into the offline report bundle.

Also provides the safe inline-SVG helpers the single-file renderer uses to
show branded marks without any external reference (no ``<img>``, no data-URI,
no runtime hotlink): ``workload_svg_map()`` returns decorative ``<svg>``
markup keyed by report workload key.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Final

from markupsafe import Markup

from licenselens.report.manifest import ASSET_DIRNAME, BundleFile
from licenselens.vendor_assets import (
    REPORT_WORKLOAD_TO_ICON_KEY,
    PinnedIcon,
    load_pinned_icons,
    scan_svg_safety,
)

_ICON_LOGICAL_PREFIX: Final = "icon-"
_INLINE_ICON_SIZE: Final = 16

_XML_DECLARATION_RE: Final = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)
_SVG_OPEN_RE: Final = re.compile(r"<svg\b([^>]*)>", re.IGNORECASE | re.DOTALL)
# Presentational root attributes the inliner replaces with the decorative set.
# `\b` guards keep names like `viewBox` (which contains `x=`) intact.
_SVG_STRIPPED_ATTR_RE: Final = re.compile(
    r"""(?:
        \b(?:width|height|id|data-name|version|x|y|style|enable-background)
        \s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+)
      | xml:space\s*=\s*(?:"[^"]*"|'[^']*')
    )""",
    re.IGNORECASE | re.VERBOSE,
)
_COLLAPSE_WS_RE: Final = re.compile(r"\s+")


def icon_bundle_files() -> tuple[BundleFile, ...]:
    """Return content-hashed-ready image ``BundleFile`` entries (sorted)."""
    files: list[BundleFile] = []
    for icon in load_pinned_icons():
        suffix = PurePosixPath(icon.relative_path).suffix.lower()
        logical = f"{_ICON_LOGICAL_PREFIX}{icon.icon_key}{suffix}"
        files.append(BundleFile(logical, icon.content, icon.media_type, "image"))
    return tuple(sorted(files, key=lambda item: item.logical_name))


def workload_icon_urls(files: tuple[BundleFile, ...]) -> dict[str, str]:
    """Map report workload keys to entry-relative hashed asset paths."""
    icon_key_to_path: dict[str, str] = {}
    for file in files:
        if file.kind != "image":
            continue
        stem = PurePosixPath(file.logical_name).stem
        if not stem.startswith(_ICON_LOGICAL_PREFIX):
            continue
        icon_key = stem.removeprefix(_ICON_LOGICAL_PREFIX)
        digest = hashlib.sha256(file.content).hexdigest()[:16]
        hashed = f"{stem}-{digest}{PurePosixPath(file.logical_name).suffix}"
        icon_key_to_path[icon_key] = f"{ASSET_DIRNAME}/{hashed}"

    urls: dict[str, str] = {}
    for workload, icon_key in sorted(REPORT_WORKLOAD_TO_ICON_KEY.items()):
        path = icon_key_to_path.get(icon_key)
        if path is not None:
            urls[workload] = path
    return urls


def inline_svg_markup(icon: PinnedIcon, *, size: int = _INLINE_ICON_SIZE) -> Markup:
    """Return decorative inline ``<svg>`` markup for a pinned SVG icon.

    Fails closed on non-SVG icons and on unsafe SVG content (``<script>``,
    external ``href``/``src``/``url(http…)`` loads). The XML declaration and
    presentational root attributes (``width``/``height``/``id``/``style`` …)
    are stripped and replaced with the decorative attribute set both renderers
    contract on: ``class="workload-icon"``, fixed inline size, ``aria-hidden``
    and ``focusable="false"``. ``viewBox`` and inner content (gradient defs,
    ``<title>``) are preserved verbatim, so the mark stays identical to the
    vendored upstream bytes.
    """
    if icon.media_type != "image/svg+xml":
        raise ValueError(f"cannot inline non-SVG icon {icon.icon_key!r}")
    text = icon.content.decode("utf-8")
    problems = scan_svg_safety(text)
    if problems:
        raise ValueError(f"unsafe SVG icon {icon.icon_key!r}: {'; '.join(problems)}")

    text = _XML_DECLARATION_RE.sub("", text)

    def _rewrite_root(match: re.Match[str]) -> str:
        attrs = _SVG_STRIPPED_ATTR_RE.sub("", match.group(1))
        attrs = _COLLAPSE_WS_RE.sub(" ", attrs).strip()
        return (
            "<svg "
            + attrs
            + f' class="workload-icon" width="{size}" height="{size}"'
            + ' aria-hidden="true" focusable="false">'
        )

    return Markup(_SVG_OPEN_RE.sub(_rewrite_root, text, count=1))


def workload_svg_map() -> dict[str, Markup]:
    """Map report workload keys to safe inline SVG markup (SVG icons only).

    Deterministic: derived from ``load_pinned_icons()`` (path-sorted) plus the
    static ``REPORT_WORKLOAD_TO_ICON_KEY`` mapping. Workloads whose pinned
    asset is a PNG (no upstream SVG mark exists at the pinned commit) are
    absent — the single-file renderer shows the visible text label alone for
    those, while the bundle keeps serving their hashed PNG via ``<img>``.
    """
    markup_by_key: dict[str, Markup] = {}
    for icon in load_pinned_icons():
        if icon.media_type == "image/svg+xml":
            markup_by_key[icon.icon_key] = inline_svg_markup(icon)

    svg_map: dict[str, Markup] = {}
    for workload, icon_key in sorted(REPORT_WORKLOAD_TO_ICON_KEY.items()):
        markup = markup_by_key.get(icon_key)
        if markup is not None:
            svg_map[workload] = markup
    return svg_map
