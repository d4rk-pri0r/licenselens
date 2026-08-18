"""HTML autoescape regression tests for the Security License Lens report.

These tests lock the boundary: every dynamic value rendered through the Jinja
``Environment`` in ``licenselens.report.html`` must be HTML-escaped, because the
report template's file extension is ``.j2`` and extension-based autoescape
(``select_autoescape(["html", "xml"])``) silently matched *nothing* — leaving
every ``{{ }}`` rendering raw. The fix is ``autoescape=True`` on the
``Environment``, uniformly, not per-field ``|safe``/``|forceescape``.

The malicious payload (``<script>alert(1)</script>``) is already carried by
``tests.report_fixtures.comprehensive_report`` in ``tenant_display_name`` and
``warnings``; these tests reuse that fixture rather than re-inventing it.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

import html5lib

from licenselens.models import ScanResult
from licenselens.report.html import write_html_report
from tests.report_fixtures import comprehensive_report

# ---------------------------------------------------------------------------
# Parsing helpers (html5lib + ElementTree — mirrors tests/test_report_render.py)
# ---------------------------------------------------------------------------


def parse_html(html: str) -> ET.Element:
    """Parse HTML5 into a namespace-free ElementTree and return its root element."""
    tree = html5lib.parse(html, treebuilder="etree", namespaceHTMLElements=False)
    return tree.getroot() if hasattr(tree, "getroot") else tree  # type: ignore[return-value]


def render(result: ScanResult, tmp_path: Path) -> str:
    out = write_html_report(result, tmp_path / "report.html")
    return out.read_text(encoding="utf-8")


def text_of(el: ET.Element) -> str:
    """Full text content of an element subtree (mirrors ElementTree itertext)."""
    chunks: list[str] = []
    for node in el.iter():
        if node.text:
            chunks.append(node.text)
        if node.tail:
            chunks.append(node.tail)
    return "".join(chunks)


# ---------------------------------------------------------------------------
# Fixtures carry the payload; these are the exact escaped renderings Jinja2
# (markupsafe) must produce once autoescape=True. Hardcoded — never derived
# from the output under test.
# ---------------------------------------------------------------------------

ESCAPED_PAYLOAD = "&lt;script&gt;alert(1)&lt;/script&gt;"
ESCAPED_TENANT_NAME = "Contoso &lt;script&gt;alert(1)&lt;/script&gt;"

# Injection values for fields the fixture leaves benign, plus their escaped forms.
INJECTED_SUMMARY = "Use <b>MFA</b> & conditional access."
INJECTED_SUMMARY_ESCAPED = "Use &lt;b&gt;MFA&lt;/b&gt; &amp; conditional access."
INJECTED_SKU = "SKU<1>&part"
INJECTED_SKU_ESCAPED = "SKU&lt;1&gt;&amp;part"
INJECTED_PLAN = "Plan<2>&svc"
INJECTED_PLAN_ESCAPED = "Plan&lt;2&gt;&amp;svc"

# Static Microsoft admin deep link with a query string (`&` and `=`) to prove the
# `href` attribute is attribute-escaped while still decoding to the same URL.
LINK_WITH_QUERY = "https://admin.microsoft.com/#/Security?foo=1&bar=2"

SECTION_HEADINGS = [
    "Where you stand",
    "What matters most",
    "What you're paying for",
    "Findings",
]


# ---------------------------------------------------------------------------
# The payload must be escaped, never parsed as live markup
# ---------------------------------------------------------------------------


def test_malicious_payload_is_escaped_in_raw_html(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    # Escaped form is present ...
    assert ESCAPED_PAYLOAD in html, "escaped payload literal missing from raw HTML"
    # ... and the raw <script> markup is absent.
    assert "<script>alert(1)</script>" not in html, "raw <script> node leaked into output"


def test_no_parsed_script_element_carries_alert_payload(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    for script in root.iter("script"):
        assert "alert(1)" not in text_of(script), "a parsed <script> element contains alert(1)"


# ---------------------------------------------------------------------------
# Dynamic text fields are escaped (no raw <, >, & in the emitted markup)
# ---------------------------------------------------------------------------


def test_tenant_name_and_warnings_are_escaped(tmp_path: Path) -> None:
    result = comprehensive_report()
    html = render(result, tmp_path)

    assert ESCAPED_TENANT_NAME in html, "escaped tenant display name missing"
    assert "Contoso <script>alert(1)</script>" not in html, "tenant name leaked raw markup"

    # Each warning is escaped verbatim.
    escaped_warnings = [
        ESCAPED_PAYLOAD,
        "Ampersand &amp; less-than &lt; and greater-than &gt; appear here.",
        "Single &#39;quotes&#39; and &#34;double quotes&#34; appear here.",
    ]
    for warning, escaped in zip(result.warnings, escaped_warnings, strict=True):
        assert escaped in html, f"escaped warning missing: {warning!r}"
        assert warning not in html, f"warning leaked raw markup: {warning!r}"


def test_injected_text_fields_are_escaped(tmp_path: Path) -> None:
    result = comprehensive_report().model_copy(deep=True)
    result.findings[0].summary = INJECTED_SUMMARY
    result.subscribed_skus[0].sku_part_number = INJECTED_SKU
    result.subscribed_skus[0].service_plans[0].service_plan_name = INJECTED_PLAN

    html = render(result, tmp_path)

    assert INJECTED_SUMMARY_ESCAPED in html, "summary not escaped"
    assert INJECTED_SUMMARY not in html, "summary leaked raw markup"
    assert INJECTED_SKU_ESCAPED in html, "sku_part_number not escaped"
    assert INJECTED_SKU not in html, "sku_part_number leaked raw markup"
    assert INJECTED_PLAN_ESCAPED in html, "service_plan_name not escaped"
    assert INJECTED_PLAN not in html, "service_plan_name leaked raw markup"


# ---------------------------------------------------------------------------
# Attribute escaping: `href` must be attribute-escaped yet decode to the same URL
# ---------------------------------------------------------------------------


def test_deep_link_href_escapes_ampersand(tmp_path: Path) -> None:
    result = comprehensive_report().model_copy(deep=True)
    result.findings[0].deep_link = LINK_WITH_QUERY

    html = render(result, tmp_path)
    assert "foo=1&amp;bar=2" in html, "href ampersand not attribute-escaped to &amp;"
    assert "foo=1&bar=2" not in html, "href ampersand leaked unescaped"

    root = parse_html(html)
    hrefs = [e.attrib.get("href") for e in root.iter("a") if "href" in e.attrib]
    assert LINK_WITH_QUERY in hrefs, "escaped href did not decode back to the original URL"


# ---------------------------------------------------------------------------
# Baseline: same structure, no injected element
# ---------------------------------------------------------------------------


def test_baseline_sections_and_no_injected_element(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))

    h2_texts = [text_of(h).strip() for h in root.iter("h2")]
    for heading in SECTION_HEADINGS:
        assert heading in h2_texts, f"missing section heading {heading!r}"

    scripts = list(root.iter("script"))
    assert len(scripts) == 1, f"expected exactly one inline <script>, found {len(scripts)}"
    assert "alert(1)" not in text_of(scripts[0]), "inline script contaminated with payload"
