"""RED contracts: manual/dynamic mode truth (AF-B, T05, T19).

Capability closure (AF-D) lives in ``test_red_contracts_capability_closure.py``
and is owned by todo 13.
"""

from __future__ import annotations

from pathlib import Path

from licenselens.catalog._reference_models import SupportState
from licenselens.catalog.reference import build_reference_model

ROOT = Path(__file__).resolve().parents[1]
CHECKS_MD = ROOT / "docs" / "reference" / "checks.md"

# Seven manual checks locked by the audit (AF-B). Listed explicitly so this
# contract does not depend on the forbidden legacy map module. (Originally nine;
# pur-insider-risk-readiness and pur-ediscovery-readiness converted to direct
# Graph evidence by the proxy/manual→direct conversion.)
MANUAL_CHECK_IDS: frozenset[str] = frozenset(
    {
        "id-idprotect-notify-high-risk",
        "id-logs-to-soc",
        "id-guest-invite-domains",
        "mdo-alert-policies-enabled",
        "mdo-audit-retention",
        "pur-communication-compliance-readiness",
        "az-cspm-out-of-scope",
    }
)
assert len(MANUAL_CHECK_IDS) == 7

DYNAMIC_EMAIL_CHECK_ID = "mdo-p2-policies-default"


def test_seven_manual_checks_render_manual_in_reference_model() -> None:
    """Reference model must label all seven manual checks as ``manual``, not ``direct``."""
    model = build_reference_model()
    by_id = {check.id: check for check in model.checks}

    missing = sorted(MANUAL_CHECK_IDS - set(by_id))
    assert not missing, f"manual checks missing from reference model: {missing}"

    non_manual = {
        check_id: by_id[check_id].support_state.value
        for check_id in sorted(MANUAL_CHECK_IDS)
        if by_id[check_id].support_state.value != "manual"
    }
    assert not non_manual, (
        "manual checks must render support_state=manual in the reference model; "
        f"still non-manual: {non_manual} (AF-B)"
    )


def test_seven_manual_checks_render_manual_in_checks_markdown() -> None:
    """Generated ``docs/reference/checks.md`` must show ``| manual |`` for each manual check."""
    text = CHECKS_MD.read_text(encoding="utf-8")
    failures: list[str] = []
    for check_id in sorted(MANUAL_CHECK_IDS):
        row = next(
            (
                line
                for line in text.splitlines()
                if f"`{check_id}`" in line and line.startswith("|")
            ),
            None,
        )
        if row is None:
            failures.append(f"{check_id}: row missing")
            continue
        # Column order: id | collector | support | ...
        if "| manual |" not in row and "| `manual` |" not in row:
            failures.append(f"{check_id}: expected manual support column, row={row!r}")
    assert not failures, "checks.md manual-mode truth failures (AF-B): " + "; ".join(failures)


def test_support_state_includes_manual_and_dynamic_descriptors() -> None:
    """SupportState must distinguish manual and dynamic (direct-first/proxy-fallback) modes."""
    values = {member.value for member in SupportState}
    assert "manual" in values, (
        "SupportState lacks 'manual'; reference model currently flattens manuals to direct (AF-B)"
    )
    dynamic_ok = "dynamic" in values or any(
        "direct" in value and "proxy" in value for value in values
    )
    assert dynamic_ok, (
        "SupportState lacks a dynamic direct-first/proxy-fallback descriptor; "
        f"members={sorted(values)} (T19)"
    )


def test_dynamic_email_check_discloses_direct_first_proxy_fallback() -> None:
    """``mdo-p2-policies-default`` must not be a static proxy label in the reference model."""
    model = build_reference_model()
    check = next(item for item in model.checks if item.id == DYNAMIC_EMAIL_CHECK_ID)
    state = check.support_state.value
    assert state != "proxy", (
        "dynamic MDO check must not render as static proxy; "
        "disclose direct-first/proxy-fallback (dynamic) instead (T19)"
    )
    assert state != "direct", (
        "dynamic MDO check must not render as static direct; "
        "disclose direct-first/proxy-fallback (dynamic) instead (T19)"
    )
    assert "dynamic" in state or ("direct" in state and "proxy" in state), (
        f"dynamic MDO check support_state={state!r} does not disclose "
        "direct-first/proxy-fallback (T19)"
    )
