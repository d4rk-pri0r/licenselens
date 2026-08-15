from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import assert_never

from licenselens.config_models import (
    AssessmentProfile,
    CollectionComparator,
    CustomRule,
    CustomRuleCondition,
    RuleOperator,
)
from licenselens.engine.custom_rule_findings import errored_custom_finding, matched_custom_finding
from licenselens.engine.selectors import (
    RuleScalar,
    RuleValue,
    SelectorContext,
    SelectorLookupError,
    select_values,
)
from licenselens.models import Finding
from licenselens.schema_contracts import CollectionSummary, JsonValue


@dataclass(frozen=True, slots=True)
class CustomRuleEvaluationError(Exception):
    diagnostic: str

    def __str__(self) -> str:
        return self.diagnostic


@dataclass(frozen=True, slots=True)
class CustomRuleLimits:
    max_rules: int = 64
    max_conditions_per_rule: int = 12
    max_string_length: int = 512
    max_value_items: int = 128
    max_value_depth: int = 8
    max_steps: int = 10_000
    max_seconds: float = 0.25


@dataclass(frozen=True, slots=True)
class CustomRuleContext:
    findings: list[Finding]
    tenant_domains: list[str]
    sensitive_users: list[str]
    collection_summaries: list[CollectionSummary]
    profile_ids: list[str]

    def selector_context(self) -> SelectorContext:
        return SelectorContext(
            findings=self.findings,
            tenant_domains=self.tenant_domains,
            sensitive_users=self.sensitive_users,
            collection_summaries=self.collection_summaries,
        )


@dataclass(frozen=True, slots=True)
class _Budget:
    limits: CustomRuleLimits
    started_at: float
    steps: int = 0

    def tick(self) -> _Budget:
        steps = self.steps + 1
        elapsed = perf_counter() - self.started_at
        if steps > self.limits.max_steps or elapsed > self.limits.max_seconds:
            raise CustomRuleEvaluationError("custom rule evaluation cap exceeded")
        return _Budget(limits=self.limits, started_at=self.started_at, steps=steps)


def compare_rule_values(
    operator: RuleOperator | str,
    actual: JsonValue,
    expected: JsonValue,
) -> bool:
    try:
        parsed = RuleOperator(operator)
    except ValueError as exc:
        raise CustomRuleEvaluationError(f"unknown operator: {operator}") from exc
    match parsed:
        case RuleOperator.EQ:
            return _equal_scalar(actual, expected)
        case RuleOperator.NE:
            return not _equal_scalar(actual, expected)
        case RuleOperator.IN:
            return _scalar(actual) in _scalar_list(expected)
        case RuleOperator.NOT_IN:
            return _scalar(actual) not in _scalar_list(expected)
        case RuleOperator.GT:
            return _number(actual) > _number(expected)
        case RuleOperator.GTE:
            return _number(actual) >= _number(expected)
        case RuleOperator.LT:
            return _number(actual) < _number(expected)
        case RuleOperator.LTE:
            return _number(actual) <= _number(expected)
        case RuleOperator.EXISTS:
            return actual is not None
        case unreachable:
            assert_never(unreachable)


def evaluate_custom_rules(
    profile: AssessmentProfile,
    context: CustomRuleContext,
    *,
    limits: CustomRuleLimits | None = None,
) -> list[Finding]:
    active_limits = limits or CustomRuleLimits()
    budget = _Budget(limits=active_limits, started_at=perf_counter())
    try:
        _check_rule_collection(profile.custom_rules, active_limits)
    except CustomRuleEvaluationError as exc:
        return [
            errored_custom_finding(
                str(profile.id),
                "custom-rule-caps",
                str(exc),
                context.profile_ids,
            )
        ]
    results: list[Finding] = []
    for rule in profile.custom_rules:
        try:
            budget = budget.tick()
            _check_rule(rule, active_limits)
            matched, budget = _rule_matches(rule, context.selector_context(), budget)
            if matched:
                results.append(matched_custom_finding(rule, str(profile.id), context.profile_ids))
        except (CustomRuleEvaluationError, SelectorLookupError, RecursionError) as exc:
            diagnostic = (
                "custom rule value nested too deep" if isinstance(exc, RecursionError) else str(exc)
            )
            results.append(
                errored_custom_finding(
                    str(profile.id),
                    str(rule.id),
                    diagnostic,
                    context.profile_ids,
                )
            )
    return results


def _rule_matches(
    rule: CustomRule,
    context: SelectorContext,
    budget: _Budget,
) -> tuple[bool, _Budget]:
    for condition in rule.conditions:
        budget = budget.tick()
        matched, budget = _condition_matches(condition, context, budget)
        if not matched:
            return False, budget
    budget = budget.tick()
    return _condition_matches(rule, context, budget)


def _condition_matches(
    condition: CustomRule | CustomRuleCondition,
    context: SelectorContext,
    budget: _Budget,
) -> tuple[bool, _Budget]:
    values = select_values(condition.selector, context)
    collection = condition.collection or CollectionComparator.ANY
    match collection:
        case CollectionComparator.ANY:
            for value in values:
                budget = budget.tick()
                if compare_rule_values(condition.operator, _json_value(value), condition.value):
                    return True, budget
            return False, budget
        case CollectionComparator.ALL:
            if not values:
                return False, budget
            for value in values:
                budget = budget.tick()
                if not compare_rule_values(condition.operator, _json_value(value), condition.value):
                    return False, budget
            return True, budget
        case CollectionComparator.COUNT:
            budget = budget.tick()
            matched = compare_rule_values(condition.operator, len(values), condition.value)
            return matched, budget
        case unreachable:
            assert_never(unreachable)


def _check_rule_collection(rules: list[CustomRule], limits: CustomRuleLimits) -> None:
    if len(rules) > limits.max_rules:
        raise CustomRuleEvaluationError("too many custom rules")


def _check_rule(rule: CustomRule, limits: CustomRuleLimits) -> None:
    if len(rule.conditions) > limits.max_conditions_per_rule:
        raise CustomRuleEvaluationError("too many custom rule conditions")
    for text in (str(rule.id), rule.title, rule.description, rule.rationale, *rule.references):
        if len(text) > limits.max_string_length:
            raise CustomRuleEvaluationError("custom rule string too large")
    _check_value(rule.value, limits)
    for condition in rule.conditions:
        _check_value(condition.value, limits)


def _check_value(value: JsonValue, limits: CustomRuleLimits, depth: int = 0) -> None:
    if depth > limits.max_value_depth:
        raise CustomRuleEvaluationError("custom rule value nested too deep")
    match value:
        case str():
            if len(value) > limits.max_string_length:
                raise CustomRuleEvaluationError("custom rule string too large")
        case list():
            if len(value) > limits.max_value_items:
                raise CustomRuleEvaluationError("custom rule collection too large")
            for item in value:
                _check_value(item, limits, depth + 1)
        case dict():
            if len(value) > limits.max_value_items:
                raise CustomRuleEvaluationError("custom rule collection too large")
            for key, item in value.items():
                if len(key) > limits.max_string_length:
                    raise CustomRuleEvaluationError("custom rule string too large")
                _check_value(item, limits, depth + 1)
        case int() | float() | bool() | None:
            return
        case unreachable:
            assert_never(unreachable)


def _scalar(value: JsonValue) -> RuleScalar | None:
    match value:
        case str() | int() | float() | bool() | None:
            return value
        case list() | dict():
            raise CustomRuleEvaluationError("custom rule comparison type mismatch")
        case unreachable:
            assert_never(unreachable)


def _equal_scalar(left: JsonValue, right: JsonValue) -> bool:
    actual = _scalar(left)
    expected = _scalar(right)
    if type(actual) is not type(expected):
        return False
    return actual == expected


def _number(value: JsonValue) -> int | float:
    match value:
        case bool() | str() | list() | dict() | None:
            raise CustomRuleEvaluationError("custom rule comparison type mismatch")
        case int() | float():
            return value
        case unreachable:
            assert_never(unreachable)


def _scalar_list(value: JsonValue) -> tuple[RuleScalar | None, ...]:
    match value:
        case list():
            return tuple(_scalar(item) for item in value)
        case str() | int() | float() | bool() | dict() | None:
            raise CustomRuleEvaluationError("custom rule comparison type mismatch")
        case unreachable:
            assert_never(unreachable)


def _json_value(value: RuleValue) -> JsonValue:
    match value:
        case tuple():
            return list(value)
        case str() | int() | float() | bool() | None:
            return value
        case unreachable:
            assert_never(unreachable)
