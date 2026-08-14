#!/usr/bin/env python3
"""Deterministically regenerate the committed sample reports and README screenshots.

The committed ``examples/sample-report/security-license-lens-report.{html,json,md}``
and ``docs/images/report-*.png`` are produced by this script from the offline
dry-run scan, mirroring the ``licenselens demo`` path (``build_auth_context`` with
``AuthMode.DRY_RUN`` and no tenant id, so the scan falls through to the same
zero-GUID tenant the demo reports). The wall-clock timestamp is pinned to a fixed
constant so the three report files are byte-reproducible across runs; the
screenshots are captured at fixed CSS-pixel viewports with motion reduced and no
network access.

Run:  uv run python scripts/regenerate_report_assets.py

Exits non-zero if the generated HTML carries a legacy AI-dashboard signature
(violet accents, radial-gradient, color-mix(), pill/circular border radii, old
headings/tagline) or a dropped emoji, or if the browser issues an http(s) request.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.models import ScanResult
from licenselens.report import write_html_report, write_json_report, write_markdown_report

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = REPO_ROOT / "examples" / "sample-report"
IMAGES_DIR = REPO_ROOT / "docs" / "images"

# Frozen scan timestamp; ``ScanResult.display_scanned_at`` derives from it.
SAMPLE_SCANNED_AT = "2026-08-13T00:00:00+00:00"

HTML_PATH = SAMPLE_DIR / "security-license-lens-report.html"
JSON_PATH = SAMPLE_DIR / "security-license-lens-report.json"
MD_PATH = SAMPLE_DIR / "security-license-lens-report.md"

# (filename, width, height, capture kind)
SCREENSHOTS: tuple[tuple[str, int, int, str], ...] = (
    ("report-hero.png", 1280, 900, "hero"),
    ("report-findings.png", 1280, 900, "findings"),
    ("report-mobile.png", 375, 1280, "mobile"),
)

# Tokens the redesigned report must carry (from DESIGN.md, the "Color" section).
NEW_DESIGN_TOKENS: tuple[str, ...] = (
    "--canvas: #0f1114",
    "--surface-1: #16191d",
    "--surface-2: #1c2025",
    "--surface-3: #242930",
    "--surface-4: #2c323b",
    "--accent: #88b4d8",
    "--accent-hover: #a3c7e4",
    "--accent-focus: #b8d6ee",
    "--accent-print: #2c5a7d",
    "--state-action: #ff737a",
    "--state-ok: #67c991",
)

# Legacy signatures the redesign removed: violet/navy/brass accents, warm
# ledger stock, radial gradients, color-mix(), pill/circular radii, and old copy.
LEGACY_SIGNATURES: tuple[str, ...] = (
    "#9b8cff",
    "#b0a4ff",
    "#c7beff",
    "#0b1220",
    "#121a2b",
    "#5b9dff",
    "#b9a06a",
    "#cbb683",
    "#ddcca8",
    "#594818",
    "--canvas: #11110f",
    "--surface-1: #171714",
    "var(--bg)",
    "var(--panel)",
    "var(--muted)",
    "radial-gradient",
    "color-mix(",
    "border-radius: 999px",
    "border-radius: 12px",
    "border-radius: 50%",
    "Your security at a glance",
    "How to read this report",
    "What you already pay for",
    "Top things to do first",
    "Where you may not be getting the full benefit",
    "The security you already own (and ignore)",
)

# Emoji the plain-language redesign dropped (U+23F1 stopwatch, U+1F465 busts).
FORBIDDEN_EMOJI: tuple[str, ...] = ("\u23f1", "\U0001f465")

# Fixed settle for fonts/layout after load and after opening a disclosure.
SETTLE_MS = 300


def build_result() -> ScanResult:
    """Run the offline dry-run scan and pin the wall-clock timestamp.

    Mirrors ``cli.demo_cmd`` / ``cli.scan_cmd``: ``AuthMode.DRY_RUN`` with no
    tenant id, so ``run_scan`` falls through to the demo's zero-GUID tenant and
    the committed sample JSON stays byte-identical except for ``scanned_at``.
    """
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    result.scanned_at = SAMPLE_SCANNED_AT
    return result


def write_reports(result: ScanResult) -> tuple[Path, Path, Path]:
    """Write the three committed sample reports to ``examples/sample-report/``."""
    html_path = write_html_report(result, HTML_PATH)
    json_path = write_json_report(result, JSON_PATH)
    md_path = write_markdown_report(result, MD_PATH)
    return html_path, json_path, md_path


def sha256(path: Path) -> str:
    """Hex SHA-256 digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_size(path: Path) -> tuple[int, int]:
    """Read width/height from a PNG's IHDR chunk (big-endian, offset 16..24)."""
    data = path.read_bytes()
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


def check_html(html: str) -> list[str]:
    """Return a list of design-token problems (empty means the HTML passes)."""
    problems: list[str] = []
    for token in NEW_DESIGN_TOKENS:
        if token not in html:
            problems.append(f"missing new design token: {token!r}")
    for signature in LEGACY_SIGNATURES:
        if signature in html:
            problems.append(f"legacy AI-dashboard signature still present: {signature!r}")
    for emoji in FORBIDDEN_EMOJI:
        if emoji in html:
            problems.append(f"forbidden emoji still present: U+{ord(emoji):04X}")
    return problems


def capture_screenshots(html_path: Path) -> dict[str, dict[str, object]]:
    """Capture the three screenshots with Playwright (no network, reduced motion)."""
    from playwright.sync_api import sync_playwright

    uri = html_path.resolve().as_uri()
    shots: dict[str, dict[str, object]] = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            for name, width, height, kind in SCREENSHOTS:
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    device_scale_factor=1,
                    reduced_motion="reduce",
                )
                page = context.new_page()
                http_requests: list[str] = []
                page.on(
                    "request",
                    lambda request, reqs=http_requests: reqs.append(request.url),
                )
                page.goto(uri, wait_until="load")
                page.wait_for_timeout(SETTLE_MS)
                if kind == "findings":
                    heading = page.locator("h2", has_text="Assessment findings").first
                    heading.evaluate("el => el.scrollIntoView({block: 'start'})")
                    page.locator("article.finding").first.locator("details.tech > summary").click()
                    page.wait_for_timeout(SETTLE_MS)
                target = IMAGES_DIR / name
                target.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(target), scale="css")
                shots[name] = {
                    "http_requests": [
                        u for u in http_requests if u.startswith(("http://", "https://"))
                    ],
                    "width": width,
                    "height": height,
                }
                context.close()
        finally:
            browser.close()
    return shots


def main() -> int:
    result = build_result()
    html_path, json_path, md_path = write_reports(result)

    problems = check_html(html_path.read_text(encoding="utf-8"))
    shots = capture_screenshots(html_path)

    print("=== SHA-256 manifest ===")
    for label, path in (("html", html_path), ("json", json_path), ("md", md_path)):
        print(f"{label:4} {sha256(path)}  {path.relative_to(REPO_ROOT)}")

    print("\n=== Screenshots ===")
    for name, width, height, _ in SCREENSHOTS:
        target = IMAGES_DIR / name
        w, h = png_size(target)
        reqs = shots[name]["http_requests"]
        print(f"{name:18} {w}x{h} (requested {width}x{height}) http-requests={len(reqs)}")

    failed = False
    if problems:
        failed = True
        print("\n=== HTML design-token problems ===")
        for problem in problems:
            print(f"  FAIL: {problem}")
    else:
        print(
            "\nHTML design tokens: OK"
            " (new tokens present, no legacy AI-dashboard signatures, no emoji)"
        )

    net_failures = [n for n, s in shots.items() if s["http_requests"]]
    if net_failures:
        failed = True
        for name in net_failures:
            print(f"  FAIL: {name} issued http(s) requests: {shots[name]['http_requests']}")
    else:
        print("Zero-network: OK (no http(s) requests across all three captures)")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
