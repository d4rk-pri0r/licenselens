from __future__ import annotations

from collections.abc import Sequence

import pytest

from licenselens.auth import AuthMode, build_auth_context
from licenselens.config_models import AssessmentProfile, RuleOperator
from licenselens.engine.custom_rules import (
    CustomRuleContext,
    CustomRuleEvaluationError,
    CustomRuleLimits,
    compare_rule_values,
    evaluate_custom_rules,
)
from licenselens.engine.profiles import compose_profile
from licenselens.engine.runner import run_scan
from licenselens.models import (
    CheckPack,
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.schema_contracts import CollectionStatus, CollectionSummary, EvaluationMode

type JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


def _finding(
    check_id: str,
    *,
    status: FindingStatus = FindingStatus.GAP,
    severity: Severity = Severity.HIGH,
    entitlements: Sequence[str] = (),
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.IDENTITY,
        status=status,
        severity=severity,
        value_impact=ValueImpact.MEDIUM,
        summary="Finding under test.",
        entitlements_used=list(entitlements),
        pack=CheckPack.IDENTITY,
        confidence=Confidence.HIGH,
        evaluation_mode=EvaluationMode.DIRECT,
    )


def _profile(
    *,
    custom_rules: list[dict[str, JsonValue]],
    profile_id: str = "rule-prof",
) -> AssessmentProfile:
    return AssessmentProfile.model_validate(
        {"schema_version": "1.0", "id": profile_id, "name": "Rules", "custom_rules": custom_rules}
    )


def test_compare_rule_values_covers_allowed_operator_matrix() -> None:
    # Given: every schema-allowed comparator with happy and boundary examples.
    cases = [
        (RuleOperator.EQ, "gap", "gap", True),
        (RuleOperator.EQ, "gap", "ok", False),
        (RuleOperator.EQ, 1, True, False),
        (RuleOperator.EQ, 1, 1.0, False),
        (RuleOperator.NE, "gap", "ok", True),
        (RuleOperator.NE, "gap", "gap", False),
        (RuleOperator.IN, "high", ["critical", "high"], True),
        (RuleOperator.IN, "medium", ["critical", "high"], False),
        (RuleOperator.NOT_IN, "medium", ["critical", "high"], True),
        (RuleOperator.NOT_IN, "high", ["critical", "high"], False),
        (RuleOperator.GT, 3, 2, True),
        (RuleOperator.GT, 3, 3, False),
        (RuleOperator.GTE, 3, 3, True),
        (RuleOperator.GTE, 2, 3, False),
        (RuleOperator.LT, 2, 3, True),
        (RuleOperator.LT, 3, 3, False),
        (RuleOperator.LTE, 3, 3, True),
        (RuleOperator.LTE, 4, 3, False),
        (RuleOperator.EXISTS, "anything", None, True),
        (RuleOperator.EXISTS, 0, None, True),
        (RuleOperator.EXISTS, False, None, True),
        (RuleOperator.EXISTS, "", None, True),
        (RuleOperator.EXISTS, None, None, False),
    ]

    # When / Then: each comparator returns the deterministic boolean contract.
    for operator, actual, expected, result in cases:
        assert compare_rule_values(operator, actual, expected) is result


@pytest.mark.parametrize(
    ("operator", "actual", "expected"),
    [
        (RuleOperator.EQ, ["gap"], "gap"),
        (RuleOperator.NE, {"k": "v"}, "gap"),
        (RuleOperator.IN, "gap", "gap"),
        (RuleOperator.IN, ["gap"], ["gap"]),
        (RuleOperator.NOT_IN, "gap", "gap"),
        (RuleOperator.NOT_IN, "gap", {"gap": True}),
        (RuleOperator.GT, "gap", 1),
        (RuleOperator.GT, True, 1),
        (RuleOperator.GTE, None, 1),
        (RuleOperator.GTE, 1, [1]),
        (RuleOperator.LT, "2", 3),
        (RuleOperator.LT, [2], 3),
        (RuleOperator.LTE, 1, [1]),
        (RuleOperator.LTE, {"n": 1}, 1),
    ],
)
def test_compare_rule_values_raises_typed_error_for_type_mismatch(
    operator: RuleOperator,
    actual: JsonValue,
    expected: JsonValue,
) -> None:
    # Given / When / Then: type-invalid comparisons fail closed without truthy coercion.
    with pytest.raises(CustomRuleEvaluationError, match="type mismatch"):
        compare_rule_values(operator, actual, expected)


def test_compare_rule_values_exists_accepts_any_json_shape_without_type_error() -> None:
    # Given: exists only checks non-null presence, including nested JSON shapes.
    # When / Then: nested values are present; null is absent.
    assert compare_rule_values(RuleOperator.EXISTS, {"nested": True}, None) is True
    assert compare_rule_values(RuleOperator.EXISTS, ["item"], None) is True
    assert compare_rule_values(RuleOperator.EXISTS, None, None) is False


def test_custom_rules_create_sanitized_findings_with_profile_provenance() -> None:
    # Given: a parsed profile rule with unsafe-looking metadata and a safe https reference.
    profile = _profile(
        custom_rules=[
            {
                "id": "high-gap<script>",
                "title": "High <script>alert(1)</script> gap",
                "selector": "finding.severity",
                "operator": "in",
                "value": ["critical", "high"],
                "description": "desc {{7*7}} $(pwsh) `sh`",
                "rationale": "fix <b>now</b>",
                "references": ["https://learn.microsoft.com/security/zero-trust/deploy/identity"],
            }
        ]
    )
    context = CustomRuleContext(
        findings=[_finding("id-ca-priv-gaps")],
        tenant_domains=["example.com"],
        sensitive_users=["breakglass@example.com"],
        collection_summaries=[],
        profile_ids=["core", "rule-prof"],
    )

    # When: custom rules are evaluated through the internal API.
    findings = evaluate_custom_rules(profile, context)

    # Then: the deterministic custom finding carries sanitized metadata and provenance only.
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.GAP
    assert finding.deep_link == "https://learn.microsoft.com/security/zero-trust/deploy/identity"
    assert "<" not in finding.title
    assert ">" not in finding.summary
    assert finding.evidence["custom_rule_id"] == "high-gapscript"
    assert finding.evidence["profile_id"] == "rule-prof"
    assert finding.evidence["profile_ids"] == ["core", "rule-prof"]


def test_custom_rule_profile_namespace_is_sanitized_for_findings() -> None:
    # Given: malicious profile and rule IDs reach the interpreter through parsed models.
    profile = _profile(
        profile_id="p<script>",
        custom_rules=[
            {
                "id": "r<script>",
                "selector": "finding.status",
                "operator": "exists",
            }
        ],
    )
    context = CustomRuleContext(
        findings=[_finding("id-ca-priv-gaps")],
        tenant_domains=[],
        sensitive_users=[],
        collection_summaries=[],
        profile_ids=["p<script>"],
    )

    # When: the custom rule becomes a Finding.
    finding = evaluate_custom_rules(profile, context)[0]

    # Then: custom metadata uses only sanitized namespace and rule identifiers.
    forbidden = set("<>;$`{} \t\n\r")
    assert finding.check_id == "custom:pscript:rscript"
    assert forbidden.isdisjoint(finding.check_id)
    assert finding.evidence["profile_id"] == "pscript"
    assert finding.evidence["profile_ids"] == ["pscript"]
    assert finding.evidence["custom_rule_id"] == "rscript"


def test_custom_rules_support_any_all_count_and_conditions() -> None:
    # Given: rules using every collection comparator over findings and collections.
    profile = _profile(
        custom_rules=[
            {
                "id": "any-gap",
                "selector": "finding.status",
                "operator": "eq",
                "value": "gap",
                "collection": "any",
            },
            {
                "id": "all-reviewed",
                "selector": "finding.status",
                "operator": "ne",
                "value": "error",
                "collection": "all",
            },
            {
                "id": "two-findings",
                "selector": "finding.status",
                "operator": "gte",
                "value": 2,
                "collection": "count",
                "conditions": [
                    {"selector": "tenant.domains", "operator": "in", "value": ["example.com"]}
                ],
            },
            {
                "id": "collection-present",
                "selector": "collection.status",
                "operator": "exists",
                "collection": "any",
            },
        ]
    )
    context = CustomRuleContext(
        findings=[
            _finding("id-ca-priv-gaps", status=FindingStatus.GAP),
            _finding("id-idprotect-off", status=FindingStatus.PARTIAL),
        ],
        tenant_domains=["example.com"],
        sensitive_users=[],
        collection_summaries=[
            CollectionSummary(collector="graph", status=CollectionStatus.SUCCESS)
        ],
        profile_ids=["rule-prof"],
    )

    # When: profile custom rules are evaluated.
    findings = evaluate_custom_rules(profile, context)

    # Then: each collection mode can produce a deterministic custom finding.
    assert [finding.evidence["custom_rule_id"] for finding in findings] == [
        "any-gap",
        "all-reviewed",
        "two-findings",
        "collection-present",
    ]


def test_unknown_selector_operator_and_payload_strings_fail_closed_without_execution() -> None:
    # Given: schema bypass fixtures carrying unknown operator/selector and payload strings.
    malicious_value = (
        "__import__('os').system('touch /tmp/licenselens-owned') {{7*7}} $(pwsh) ; rm -rf /"
    )
    profile = _profile(
        custom_rules=[
            {"id": "safe", "selector": "finding.status", "operator": "eq", "value": malicious_value}
        ]
    )
    unknown_selector = profile.custom_rules[0].model_copy(update={"selector": "tenant.secret"})
    unknown_operator = profile.custom_rules[0].model_copy(update={"operator": "matches"})
    unsafe_profile = profile.model_copy(
        update={"custom_rules": [unknown_selector, unknown_operator]}
    )
    context = CustomRuleContext(
        findings=[_finding("id-ca-priv-gaps")],
        tenant_domains=[],
        sensitive_users=[],
        collection_summaries=[],
        profile_ids=["rule-prof"],
    )

    # When: the interpreter receives untrusted strings through typed objects.
    findings = evaluate_custom_rules(unsafe_profile, context)

    # Then: both rules become error findings and payload strings are never interpreted.
    assert [finding.status for finding in findings] == [FindingStatus.ERROR, FindingStatus.ERROR]
    assert "unknown selector" in findings[0].summary
    assert "unknown operator" in findings[1].summary


@pytest.mark.parametrize(
    ("limits", "rules", "expected"),
    [
        (CustomRuleLimits(max_rules=1), [{"id": "a"}, {"id": "b"}], "too many custom rules"),
        (
            CustomRuleLimits(max_string_length=8),
            [{"id": "long", "value": "x" * 9}],
            "custom rule string too large",
        ),
        (
            CustomRuleLimits(max_value_items=2),
            [{"id": "huge", "value": ["a", "b", "c"]}],
            "custom rule collection too large",
        ),
        (
            CustomRuleLimits(max_value_items=1),
            [{"id": "dict-huge", "value": {"a": 1, "b": 2}}],
            "custom rule collection too large",
        ),
        (
            CustomRuleLimits(max_value_depth=1),
            [{"id": "deep", "value": {"a": {"b": 1}}}],
            "custom rule value nested too deep",
        ),
        (
            CustomRuleLimits(max_conditions_per_rule=0),
            [
                {
                    "id": "conds",
                    "conditions": [
                        {"selector": "finding.status", "operator": "exists"},
                    ],
                }
            ],
            "too many custom rule conditions",
        ),
        (
            CustomRuleLimits(max_steps=1),
            [{"id": "steps"}],
            "custom rule evaluation cap exceeded",
        ),
        (
            CustomRuleLimits(max_seconds=0.0),
            [{"id": "time"}],
            "custom rule evaluation cap exceeded",
        ),
    ],
)
def test_rule_caps_return_error_findings_without_misleading_success(
    limits: CustomRuleLimits,
    rules: list[dict[str, JsonValue]],
    expected: str,
) -> None:
    # Given: profiles that exceed deterministic caps.
    custom_rules = [{"selector": "finding.status", "operator": "exists"} | rule for rule in rules]
    context = CustomRuleContext(
        findings=[_finding("id-ca-priv-gaps")],
        tenant_domains=[],
        sensitive_users=[],
        collection_summaries=[],
        profile_ids=["rule-prof"],
    )

    # When: evaluation runs with tight caps.
    findings = evaluate_custom_rules(_profile(custom_rules=custom_rules), context, limits=limits)

    # Then: the outcome is explicit error, not silent success.
    assert findings[0].status is FindingStatus.ERROR
    assert expected in findings[0].summary


def test_empty_collection_comparators_fail_closed() -> None:
    # Given: no findings and no collection summaries for any/all/count selectors.
    profile = _profile(
        custom_rules=[
            {
                "id": "any-empty",
                "selector": "finding.status",
                "operator": "eq",
                "value": "gap",
                "collection": "any",
            },
            {
                "id": "all-empty",
                "selector": "finding.status",
                "operator": "ne",
                "value": "error",
                "collection": "all",
            },
            {
                "id": "count-empty",
                "selector": "finding.status",
                "operator": "eq",
                "value": 0,
                "collection": "count",
            },
        ]
    )
    context = CustomRuleContext(
        findings=[],
        tenant_domains=[],
        sensitive_users=[],
        collection_summaries=[],
        profile_ids=["rule-prof"],
    )

    # When: empty collections are evaluated.
    findings = evaluate_custom_rules(profile, context)

    # Then: any/all do not match; count eq 0 does match.
    assert [finding.evidence["custom_rule_id"] for finding in findings] == ["count-empty"]


def test_budget_ticks_per_selected_value() -> None:
    # Given: many findings and a step budget smaller than one-per-value evaluation.
    profile = _profile(
        custom_rules=[
            {
                "id": "walk",
                "selector": "finding.status",
                "operator": "eq",
                "value": "missing",
                "collection": "any",
            }
        ]
    )
    context = CustomRuleContext(
        findings=[_finding(f"check-{index}") for index in range(5)],
        tenant_domains=[],
        sensitive_users=[],
        collection_summaries=[],
        profile_ids=["rule-prof"],
    )

    # When: evaluation walks values under a tight step cap.
    findings = evaluate_custom_rules(
        profile,
        context,
        limits=CustomRuleLimits(max_steps=3),
    )

    # Then: the walk fails closed as an ERROR finding, not a silent miss.
    assert findings[0].status is FindingStatus.ERROR
    assert "cap exceeded" in findings[0].summary


def test_runner_appends_custom_profile_findings_without_cli_wiring() -> None:
    # Given: dry-run scan receives a composed profile containing shipped custom rules.
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    profile = compose_profile("identity")

    # When: the existing internal runner profile seam is used.
    result = run_scan(auth, dry_run=True, profile=profile)

    # Then: normal profile IDs serialize and custom findings include rule provenance.
    custom_findings = [
        finding for finding in result.findings if finding.check_id.startswith("custom:")
    ]
    assert result.profile_ids == ["identity"]
    assert custom_findings
    assert custom_findings[0].evidence["profile_id"] == "identity"
