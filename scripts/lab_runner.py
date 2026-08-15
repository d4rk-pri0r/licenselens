"""Redacted live-lab runner for the todo-35 validation matrix.

Loads ``catalog/lab/live-lab-matrix.yaml`` and validates it against the live
assessment registry, proves every direct check family has a pass and a fail
case against fake backends, exercises negative (permission-denied, unavailable
module, unsupported cloud, empty/large tenant) scenarios, and emits redacted
receipts. No live tenant, credential, UPN, or resource identifier is ever read
or written.

Subcommands:

* ``validate``   — structural + registry + secret audit of the matrix.
* ``probe``      — run pass/fail evaluator probes against fake backends.
* ``negative``   — run negative scenario probes against fake backends.
* ``receipt``    — emit redacted live-lab + live-lab-negative receipts.
* ``redact``     — self-check that secret-shaped input is redacted.

Usage::

    uv run python scripts/lab_runner.py validate
    uv run python scripts/lab_runner.py receipt \
        --out .omo/evidence/maturity-and-check-expansion/
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Final

import yaml

from licenselens.collectors.contracts import CloudEnvironment, EvidenceKey
from licenselens.collectors.powershell import (
    BridgeInvokeRequest,
    invoke_powershell_adapter,
)
from licenselens.collectors.powershell_result import redact_secrets
from licenselens.engine.registry import default_registry
from licenselens.models import CheckDefinition, Workload

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
MATRIX_PATH: Final = REPO_ROOT / "catalog" / "lab" / "live-lab-matrix.yaml"
RUNNER_NAME: Final = "scripts/lab_runner.py"

# Make the checked-in ``tests`` package importable when run directly (the
# negative probes reuse tests.fake_clients.FakeGraphClient).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ZERO_TENANT_ID: Final = "00000000-0000-0000-0000-000000000000"
ZERO_RESOURCE_ID: Final = "/subscriptions/00000000-0000-0000-0000-000000000000"

# Family -> check-id prefixes (mutually exclusive, collectively exhaustive over
# the 139 shipped checks).
FAMILY_PREFIXES: Final[Mapping[str, tuple[str, ...]]] = {
    "identity": ("id-",),
    "email": ("exo-", "mdo-"),
    "collaboration": ("spo-", "teams-"),
    "power": ("pp-", "pbi-"),
    "endpoint": ("endpoint-", "mde-", "mdi-", "xdr-"),
    "purview": ("pur-",),
    "sentinel": ("sen-", "az-"),
}

# Secret-shaped / tenant-identifier tokens that must never appear in emitted
# receipts. Mirrors scripts/generate_reference_docs.py SECRET_TOKENS.
SECRET_TOKENS: Final = (
    "client_secret",
    "clientsecret",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "api_key",
    "apikey",
    "authorization: bearer",
    "authorization: basic",
)

_UUID_PATTERN: Final = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_UPN_PATTERN: Final = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_RESOURCE_ID_PATTERN: Final = re.compile(r"/subscriptions/[0-9a-fA-F-]{36,}")

type Matrix = dict[str, object]
type Problems = list[str]


def redact_text(text: str) -> str:
    """Redact credential-shaped and tenant-identifier-shaped substrings."""
    cleaned = redact_secrets(text)
    for token in SECRET_TOKENS:
        cleaned = re.sub(re.escape(token), "[redacted]", cleaned, flags=re.IGNORECASE)
    cleaned = _UUID_PATTERN.sub("***", cleaned)
    cleaned = _UPN_PATTERN.sub("***@***", cleaned)
    cleaned = _RESOURCE_ID_PATTERN.sub("/subscriptions/***", cleaned)
    return cleaned


def find_identifier_leaks(text: str) -> list[str]:
    """Return tenant-identifier detections (UUID/UPN/resource) in ``text``."""
    problems: list[str] = []
    for token in _UUID_PATTERN.findall(text):
        if token.lower() not in {ZERO_TENANT_ID, "00000000-0000-0000-0000-000000000000"}:
            problems.append(f"uuid:{token}")
    for upn in _UPN_PATTERN.findall(text):
        problems.append(f"upn:{upn}")
    for resource in _RESOURCE_ID_PATTERN.findall(text):
        if ZERO_RESOURCE_ID not in resource:
            problems.append(f"resource_id:{resource}")
    return problems


def find_secret_token_leaks(text: str) -> list[str]:
    """Return secret-token-name detections in ``text`` (empty means clean)."""
    lowered = text.lower()
    return [f"secret:{token}" for token in SECRET_TOKENS if token in lowered]


def find_leaks(text: str) -> list[str]:
    """Return secret/identifier detections in ``text`` (empty means clean)."""
    return [*find_secret_token_leaks(text), *find_identifier_leaks(text)]


def load_matrix(path: Path = MATRIX_PATH) -> Matrix:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"matrix root is not a mapping: {path}")
    return data


def family_entries(matrix: Matrix) -> list[dict[str, object]]:
    families = matrix.get("families")
    if not isinstance(families, list):
        raise ValueError("matrix has no families list")
    return [f for f in families if isinstance(f, dict)]


def check_ids_by_family() -> dict[str, list[str]]:
    """Partition every shipped check id into a family using FAMILY_PREFIXES."""
    registry = default_registry()
    mapping: dict[str, list[str]] = {name: [] for name in FAMILY_PREFIXES}
    orphan: list[str] = []
    for entry in registry.evaluator_entries:
        check_id = entry.id
        matched: str | None = None
        for family, prefixes in FAMILY_PREFIXES.items():
            if any(check_id.startswith(p) for p in prefixes):
                matched = family
                break
        if matched is None:
            orphan.append(check_id)
        else:
            mapping[matched].append(check_id)
    if orphan:
        raise ValueError(f"check ids outside any family prefix: {orphan}")
    return mapping


def family_for_check(check_id: str) -> str | None:
    for family, prefixes in FAMILY_PREFIXES.items():
        if any(check_id.startswith(p) for p in prefixes):
            return family
    return None


def registry_evaluation_modes() -> dict[str, str]:
    registry = default_registry()
    return {entry.id: entry.evaluation_mode.value for entry in registry.evaluator_entries}


def validate_matrix(matrix: Matrix) -> Problems:
    """Return a list of problems (empty means the matrix is valid)."""
    problems: list[str] = []
    modes = registry_evaluation_modes()
    registry = default_registry()
    known_ids = {entry.id for entry in registry.evaluator_entries}

    raw = MATRIX_PATH.read_text(encoding="utf-8")
    problems.extend(find_identifier_leaks(raw))

    families = family_entries(matrix)
    seen_families: set[str] = set()
    for family in families:
        fid = family.get("id")
        if not isinstance(fid, str) or fid not in FAMILY_PREFIXES:
            problems.append(f"family id not recognized: {fid!r}")
            continue
        if fid in seen_families:
            problems.append(f"duplicate family id: {fid}")
        seen_families.add(fid)

        prefixes = family.get("check_prefixes")
        if tuple(prefixes or ()) != FAMILY_PREFIXES[fid]:
            problems.append(f"{fid}: check_prefixes drift from FAMILY_PREFIXES")

        proof = family.get("proof")
        if not isinstance(proof, str) or not (REPO_ROOT / proof).is_file():
            problems.append(f"{fid}: proof test file missing: {proof!r}")

        for case_key in ("pass_case", "fail_case"):
            case = family.get(case_key)
            if not isinstance(case, dict) or not case.get("checks"):
                problems.append(f"{fid}: missing {case_key}")
                continue
            for item in case["checks"]:
                cid = item.get("check_id")
                expected = item.get("expected")
                if cid not in known_ids:
                    problems.append(f"{fid}.{case_key}: unknown check id {cid!r}")
                if family_for_check(cid) != fid:
                    problems.append(f"{fid}.{case_key}: check {cid!r} belongs to another family")
                if expected not in {"ok", "gap", "partial", "error", "skipped", "not_licensed"}:
                    problems.append(f"{fid}.{case_key}: bad expected status {expected!r}")

        for mode, key in (("manual", "downgraded_manual"), ("proxy", "proxy")):
            declared = family.get(key) or []
            for cid in declared:
                if cid not in known_ids:
                    problems.append(f"{fid}.{key}: unknown check id {cid!r}")
                    continue
                if modes.get(cid) != mode:
                    problems.append(
                        f"{fid}.{key}: {cid!r} registry mode {modes.get(cid)!r} != {mode!r}"
                    )

        neg = family.get("negative_cases")
        if not isinstance(neg, list) or not neg:
            problems.append(f"{fid}: missing negative_cases")

    declared = {f["id"] for f in families}
    missing = set(FAMILY_PREFIXES) - declared
    if missing:
        problems.append(f"missing families: {sorted(missing)}")

    try:
        by_family = check_ids_by_family()
    except ValueError as exc:
        problems.append(str(exc))
        return problems
    total = sum(len(ids) for ids in by_family.values())
    if total != len(known_ids):
        problems.append(f"family partition covers {total} != {len(known_ids)} checks")
    return problems


# ---------------------------------------------------------------------------
# Pass/fail probes (fake backends). Each family proves one compliant -> ok and
# one noncompliant -> gap/partial using the real evaluator.
# ---------------------------------------------------------------------------


def _check(check_id: str, workload: Workload) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=workload)


def _workload_for(check_id: str) -> Workload:
    if check_id.startswith("exo-"):
        return Workload.EXCHANGE
    if check_id.startswith(("spo-", "teams-")):
        return Workload.COLLABORATION
    if check_id.startswith("pp-"):
        return Workload.POWER_PLATFORM
    if check_id.startswith("pbi-"):
        return Workload.POWER_BI
    if check_id.startswith("pur-"):
        return Workload.PURVIEW
    if check_id.startswith(("sen-", "az-")):
        return Workload.SENTINEL
    if check_id.startswith(("endpoint-", "mde-", "mdi-", "xdr-")):
        return Workload.ENDPOINT
    return Workload.IDENTITY


@dataclass(frozen=True, slots=True)
class Probe:
    family: str
    check_id: str
    evidence: dict[str, object]


@dataclass
class ProbeResult:
    probe: Probe
    status: str
    observed: str
    is_pass: bool

    def __bool__(self) -> bool:
        return self.is_pass


def _demo_exchange() -> dict[str, object]:
    from licenselens.collectors.dns_records import DEMO_DNS_RECORDS
    from licenselens.collectors.exchange import demo_exchange_evidence

    evidence = demo_exchange_evidence()
    evidence["dns_records"] = copy.deepcopy(DEMO_DNS_RECORDS)
    return evidence


def _demo_collaboration() -> dict[str, object]:
    from licenselens.collectors.collaboration import demo_collaboration_evidence

    return demo_collaboration_evidence()


def _demo_power() -> dict[str, object]:
    from licenselens.collectors.power_data import demo_power_data_evidence

    return demo_power_data_evidence()


def _demo_endpoint() -> dict[str, object]:
    from licenselens.collectors.intune_policy import DEMO_INTUNE_EVIDENCE_BUNDLE

    return {"intune_bundle": copy.deepcopy(DEMO_INTUNE_EVIDENCE_BUNDLE)}


def _identity_compliant() -> dict[str, object]:
    return {
        "ca_policies": [
            {
                "displayName": "Block legacy + MFA",
                "state": "enabled",
                "conditions": {
                    "users": {"includeUsers": ["All"], "excludeUsers": []},
                    "clientAppTypes": ["exchangeActiveSync", "other"],
                },
                "grantControls": {"builtInControls": ["block"]},
            }
        ],
        "break_glass_principal_ids": [],
    }


def _sentinel_compliant() -> dict[str, object]:
    return {
        "sentinel_rules": {
            "enabled_scheduled_or_nrt": 15,
            "total_rules": 20,
            "tactic_count": 5,
        }
    }


PASS_PROBES: Final[tuple[Probe, ...]] = (
    Probe("identity", "id-ca-legacy-auth-block", _identity_compliant()),
    Probe("email", "exo-dkim-enabled", _demo_exchange()),
    Probe("collaboration", "spo-default-link-specific", _demo_collaboration()),
    Probe("power", "pp-env-creation-admin-only", _demo_power()),
    Probe("endpoint", "endpoint-compliance-policy-assigned", _demo_endpoint()),
    Probe("purview", "pur-dlp-policy-present", _demo_exchange()),
    Probe("sentinel", "sen-analytics-rule-coverage", _sentinel_compliant()),
)

FAIL_PROBES: Final[tuple[Probe, ...]] = (
    Probe("identity", "id-ca-legacy-auth-block", {"ca_policies": []}),
    Probe("email", "exo-dkim-enabled", {}),
    Probe("collaboration", "spo-default-link-specific", {}),
    Probe("power", "pp-env-creation-admin-only", {}),
    Probe("endpoint", "endpoint-compliance-policy-assigned", {}),
    Probe("purview", "pur-dlp-policy-present", {}),
    Probe("sentinel", "sen-analytics-rule-coverage", {"sentinel_rules": {}}),
)


def _evaluate_probe(probe: Probe) -> str:
    from licenselens.evaluators import evaluator_for_check

    evaluator = evaluator_for_check(probe.check_id)
    result = evaluator(_check(probe.check_id, _workload_for(probe.check_id)), probe.evidence)
    return result.status.value


@cache
def run_pass_probes() -> tuple[ProbeResult, ...]:
    results: list[ProbeResult] = []
    for probe in PASS_PROBES:
        status = _evaluate_probe(probe)
        results.append(ProbeResult(probe, "ok", status, status == "ok"))
    return tuple(results)


@cache
def run_fail_probes() -> tuple[ProbeResult, ...]:
    results: list[ProbeResult] = []
    for probe in FAIL_PROBES:
        status = _evaluate_probe(probe)
        results.append(ProbeResult(probe, "non-ok", status, status in {"gap", "partial", "error"}))
    return tuple(results)


# ---------------------------------------------------------------------------
# Negative scenario probes (fake backends).
# ---------------------------------------------------------------------------


@dataclass
class NegativeResult:
    scenario: str
    mechanism: str
    expected: str
    observed: str

    @property
    def is_pass(self) -> bool:
        return self.observed != "ok"


@cache
def run_negative_probes() -> tuple[NegativeResult, ...]:
    from licenselens.evaluators import evaluator_for_check

    results: list[NegativeResult] = []

    status = evaluator_for_check("sen-analytics-rule-coverage")(
        _check("sen-analytics-rule-coverage", Workload.SENTINEL),
        {"sentinel_workspace_missing": True},
    ).status.value
    results.append(NegativeResult("missing-workspace", "evaluator", "error", status))

    envelope = invoke_powershell_adapter(
        BridgeInvokeRequest(adapter="exo_threat_policies", evidence_key=EvidenceKey("powershell")),
        executable=None,
    )
    results.append(
        NegativeResult(
            "module-unavailable", "powershell bridge", "unavailable", envelope.health.value
        )
    )

    envelope = invoke_powershell_adapter(
        BridgeInvokeRequest(
            adapter="exo_threat_policies",
            cloud=CloudEnvironment.US_GOV,
            evidence_key=EvidenceKey("powershell"),
        )
    )
    results.append(
        NegativeResult(
            "unsupported-cloud", "powershell bridge", "unsupported", envelope.health.value
        )
    )

    empty_statuses = {f.status.value for f in _run_fake_scan_empty_tenant()}
    empty_observed = (
        "not_licensed" if empty_statuses <= {"not_licensed"} else sorted(empty_statuses)
    )
    results.append(
        NegativeResult("empty-tenant", "fake graph scan", "not_licensed", empty_observed)
    )

    denied = _run_fake_scan_permission_denied()
    denied_observed = "error" if any(f.status.value == "error" for f in denied) else "no-error"
    results.append(NegativeResult("permission-denied", "fake graph scan", "error", denied_observed))

    truncated = _run_fake_scan_truncated()
    trunc_observed = (
        "partial" if any(f.status.value == "partial" for f in truncated) else "no-partial"
    )
    results.append(NegativeResult("large-tenant", "fake graph scan", "partial", trunc_observed))

    return tuple(results)


def _fake_auth():
    from licenselens.auth import AuthContext, AuthMode

    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="live-tenant")


def _e5_skus() -> dict:
    return {
        "value": [
            {
                "skuId": "e5",
                "skuPartNumber": "SPE_E5",
                "capabilityStatus": "Enabled",
                "consumedUnits": 5,
                "prepaidUnits": {"enabled": 10},
                "servicePlans": [
                    {"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "Success"}
                ],
            }
        ]
    }


def _run_fake_scan(
    monkeypatch_patch, *, skus: dict, ca_error: bool = False, truncated: bool = False
):
    from tests.fake_clients import FakeGraphClient, error, ok

    fake = FakeGraphClient()
    fake.register_list("/organization", ok({"value": [{"id": "t-1", "displayName": "LabCo"}]}))
    fake.register_list("/subscribedSkus", ok({"value": skus.get("value", [])}))
    if ca_error:
        fake.register_list("/identity/conditionalAccess/policies", error(403))
    else:
        fake.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    fake.register_list("/roleManagement/directory/roleAssignments", ok({"value": []}))
    fake.register_list("/roleManagement/directory/roleEligibilitySchedules", ok({"value": []}))
    fake.register_list("/auditLogs/signIns", ok({"value": []}))
    fake.register_get(
        "/security/secureScores",
        ok(
            {
                "value": [
                    {"id": "ss-1", "currentScore": 50.0, "maxScore": 100.0, "controlScores": []}
                ]
            }
        ),
    )
    fake.register_get(
        "/policies/identitySecurityDefaultsEnforcementPolicy",
        ok({"id": "sd-1", "isEnabled": True}),
    )
    fake.register_list("/identityGovernance/accessReviews/definitions", ok({"value": []}))

    import licenselens.engine.runner as runner_mod

    monkeypatch_patch.setattr(runner_mod, "GraphClient", lambda _auth, **_kw: fake)
    monkeypatch_patch.setattr(
        runner_mod,
        "collect_mde_machine_summary",
        lambda _auth: {
            "onboarded_machines": 1,
            "sample_size": 1,
            "count_method": "test",
            "truncated": truncated,
        },
    )
    monkeypatch_patch.setattr(
        runner_mod,
        "collect_sentinel_bundle",
        lambda _auth, _wid: {
            "sentinel_rules": {"total_rules": 0},
            "sentinel_ueba": {},
            "workspace_resource_id": None,
        },
    )
    monkeypatch_patch.setattr(
        "licenselens.collectors.workspace_discover.discover_sentinel_workspaces",
        lambda _auth: [],
    )
    from licenselens.engine.runner import run_scan

    return run_scan(_fake_auth(), dry_run=False, allow_email_proxy=True)


def _run_fake_scan_empty_tenant():
    import pytest

    with pytest.MonkeyPatch.context() as mp:
        result = _run_fake_scan(mp, skus={"value": []})
    return result.findings


def _run_fake_scan_permission_denied():
    import pytest

    with pytest.MonkeyPatch.context() as mp:
        result = _run_fake_scan(mp, skus=_e5_skus(), ca_error=True)
    return result.findings


def _run_fake_scan_truncated():
    import pytest

    with pytest.MonkeyPatch.context() as mp:
        result = _run_fake_scan(mp, skus=_e5_skus(), truncated=True)
    return result.findings


# ---------------------------------------------------------------------------
# Dry-run cross-check: every direct family is exercised against fake backends.
# ---------------------------------------------------------------------------


@dataclass
class FamilyCoverage:
    family: str
    total: int
    statuses: dict[str, int] = field(default_factory=dict)

    @property
    def exercised(self) -> bool:
        return any(status in {"ok", "gap", "partial", "error"} for status in self.statuses)


@cache
def run_dry_run_coverage() -> tuple[FamilyCoverage, ...]:
    from licenselens.auth import AuthMode, build_auth_context
    from licenselens.engine.runner import run_scan

    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)

    buckets: dict[str, Counter] = {name: Counter() for name in FAMILY_PREFIXES}
    for finding in result.findings:
        family = family_for_check(finding.check_id)
        if family is None:
            continue
        buckets[family][finding.status.value] += 1

    return tuple(
        FamilyCoverage(family=fid, total=sum(c.values()), statuses=dict(c))
        for fid, c in buckets.items()
    )


# ---------------------------------------------------------------------------
# Receipt rendering.
# ---------------------------------------------------------------------------


def _md_row(cells: Sequence[object]) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def render_happy_receipt(
    matrix: Matrix,
    pass_results: Sequence[ProbeResult],
    fail_results: Sequence[ProbeResult],
    coverage: Sequence[FamilyCoverage],
) -> str:
    modes = registry_evaluation_modes()
    lines: list[str] = [
        "# Live-lab validation matrix — redacted receipt",
        "",
        f"Runner: `{RUNNER_NAME}`",
        "Matrix: `catalog/lab/live-lab-matrix.yaml`",
        "Status: **defined + dry-run validated against fake backends — no real tenant touched**",
        "",
        "> Synthetic fixtures only. No Microsoft tenant, credential, UPN, or resource",
        "> identifier is present in this receipt. Actual live-tenant execution is",
        "> deferred to the operator following `docs/tenant-provisioning-guide.md`.",
        "",
        "## Families",
        "",
        _md_row(["Family", "Todo", "Backend", "Auth", "Direct", "Downgraded", "Proxy"]),
        _md_row(["---", "---", "---", "---", "---", "---", "---"]),
    ]
    by_family = check_ids_by_family()
    for family in family_entries(matrix):
        fid = family["id"]
        direct = sum(1 for cid in by_family[fid] if modes.get(cid) == "direct")
        manual = len(family.get("downgraded_manual") or [])
        proxy = len(family.get("proxy") or [])
        auth = ",".join(family.get("auth_modes") or [])
        lines.append(
            _md_row([fid, family.get("todo"), family.get("backend"), auth, direct, manual, proxy])
        )
    lines += [
        "",
        "## Proven pass + fail cases (fake backends)",
        "",
        _md_row(["Family", "Pass check -> ok", "Fail check -> non-ok"]),
        _md_row(["---", "---", "---"]),
    ]
    pass_map = {r.probe.family: r for r in pass_results}
    fail_map = {r.probe.family: r for r in fail_results}
    for family in family_entries(matrix):
        fid = family["id"]
        p = pass_map[fid]
        f = fail_map[fid]
        pass_cell = f"`{p.probe.check_id}` -> `{p.observed}`"
        fail_cell = f"`{f.probe.check_id}` -> `{f.observed}`"
        lines.append(_md_row([fid, pass_cell, fail_cell]))
    lines += [
        "",
        "## Dry-run coverage (fake backends)",
        "",
        _md_row(["Family", "Findings", "Statuses", "Exercised"]),
        _md_row(["---", "---", "---", "---"]),
    ]
    for c in coverage:
        statuses = ", ".join(f"{k}={v}" for k, v in sorted(c.statuses.items()))
        lines.append(_md_row([c.family, c.total, statuses, "yes" if c.exercised else "NO"]))
    lines += [
        "",
        "## Redaction",
        "",
        "- Secret tokens: none detected.",
        "- Tenant identifiers / UPNs / resource IDs: none detected.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_negative_receipt(
    negative_results: Sequence[NegativeResult],
    coverage: Sequence[FamilyCoverage],
) -> str:
    lines: list[str] = [
        "# Live-lab negative receipt — redacted",
        "",
        f"Runner: `{RUNNER_NAME}`",
        "Status: **negative scenarios validated against fake backends — no real tenant touched**",
        "",
        "Every negative case below must produce a non-pass state (never `ok`, never a",
        "false gap). Observed states are captured from fake backends only.",
        "",
        _md_row(["Scenario", "Mechanism", "Expected", "Observed"]),
        _md_row(["---", "---", "---", "---"]),
    ]
    for r in negative_results:
        marker = "correct" if r.is_pass else "MISMATCH"
        lines.append(_md_row([r.scenario, r.mechanism, r.expected, f"{r.observed} ({marker})"]))
    lines += ["", "## Dry-run family exercise", ""]
    unexercised = [c.family for c in coverage if not c.exercised]
    lines.append(f"- Unexercised direct families: {unexercised or 'none'}")
    lines += [
        "",
        "## Redaction",
        "",
        "- Secret tokens: none detected.",
        "- Tenant identifiers / UPNs / resource IDs: none detected.",
        "",
    ]
    return "\n".join(lines) + "\n"


def _probe_json(result: ProbeResult, expected: str) -> dict[str, str]:
    return {
        "family": result.probe.family,
        "check_id": result.probe.check_id,
        "expected": expected,
        "observed": result.observed,
    }


def render_json_receipt(
    matrix: Matrix,
    pass_results: Sequence[ProbeResult],
    fail_results: Sequence[ProbeResult],
    coverage: Sequence[FamilyCoverage],
    negative_results: Sequence[NegativeResult],
) -> str:
    payload = {
        "runner": RUNNER_NAME,
        "matrix": "catalog/lab/live-lab-matrix.yaml",
        "status": "defined + dry-run validated against fake backends (no real tenant touched)",
        "families": [
            {
                "id": f["id"],
                "todo": f.get("todo"),
                "backend": f.get("backend"),
                "auth_modes": f.get("auth_modes"),
                "downgraded_manual": f.get("downgraded_manual"),
                "proxy": f.get("proxy"),
                "proof": f.get("proof"),
                "pass_case": f.get("pass_case"),
                "fail_case": f.get("fail_case"),
                "negative_cases": f.get("negative_cases"),
            }
            for f in family_entries(matrix)
        ],
        "probes": {
            "pass": [_probe_json(r, "ok") for r in pass_results],
            "fail": [_probe_json(r, "non-ok") for r in fail_results],
        },
        "negative": [
            {
                "scenario": r.scenario,
                "mechanism": r.mechanism,
                "expected": r.expected,
                "observed": r.observed,
            }
            for r in negative_results
        ],
        "coverage": [
            {
                "family": c.family,
                "total": c.total,
                "statuses": c.statuses,
                "exercised": c.exercised,
            }
            for c in coverage
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def emit_receipts_text(
    matrix: Matrix,
    pass_results: Sequence[ProbeResult],
    fail_results: Sequence[ProbeResult],
    coverage: Sequence[FamilyCoverage],
    negative_results: Sequence[NegativeResult],
) -> dict[str, str]:
    return {
        "live-lab.md": render_happy_receipt(matrix, pass_results, fail_results, coverage),
        "live-lab-negative.md": render_negative_receipt(negative_results, coverage),
        "live-lab.json": render_json_receipt(
            matrix, pass_results, fail_results, coverage, negative_results
        ),
    }


def emit_receipts(out_dir: Path) -> dict[str, Path]:
    matrix = load_matrix()
    pass_results = run_pass_probes()
    fail_results = run_fail_probes()
    coverage = run_dry_run_coverage()
    negative_results = run_negative_probes()

    out_dir.mkdir(parents=True, exist_ok=True)
    contents = emit_receipts_text(matrix, pass_results, fail_results, coverage, negative_results)
    paths: dict[str, Path] = {}
    for name, content in contents.items():
        target = out_dir / name
        target.write_text(content, encoding="utf-8")
        paths[name] = target

    leaks = [*find_leaks(contents["live-lab.md"]), *find_leaks(contents["live-lab-negative.md"])]
    if leaks:
        raise RuntimeError("receipt leaks detected: " + ", ".join(leaks))

    for name, content in contents.items():
        if (out_dir / name).read_text(encoding="utf-8") != content:
            raise RuntimeError(f"receipt {name} is non-deterministic")
    return paths


def _arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Redacted live-lab runner (todo 35).")
    parser.add_argument("command", choices=["validate", "probe", "negative", "receipt", "redact"])
    parser.add_argument(
        "--out",
        type=Path,
        default=(
            REPO_ROOT / ".omo" / "evidence" / "maturity-and-check-expansion"
        ),
    )
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)

    if args.command == "redact":
        sample = (
            "client_secret=abc123 access_token=eyJhbGciOi.jwt.body "
            "user@contoso.com /subscriptions/11111111-2222-3333-4444-555555555555"
        )
        cleaned = redact_text(sample)
        print(cleaned)
        return 0 if find_leaks(cleaned) == [] else 1

    matrix = load_matrix(args.matrix)

    if args.command == "validate":
        problems = validate_matrix(matrix)
        if problems:
            print("matrix invalid:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        count = len(family_entries(matrix))
        print(f"matrix valid: {count} families, no secrets, all check ids resolve")
        return 0

    if args.command == "probe":
        pass_results = run_pass_probes()
        fail_results = run_fail_probes()
        print("pass probes:")
        for r in pass_results:
            marker = "OK" if r.is_pass else "MISMATCH"
            print(f"  {r.probe.family}: {r.probe.check_id} -> {r.observed} {marker}")
        print("fail probes:")
        for r in fail_results:
            marker = "OK" if r.is_pass else "MISMATCH"
            print(f"  {r.probe.family}: {r.probe.check_id} -> {r.observed} {marker}")
        return 0 if all(pass_results) and all(fail_results) else 1

    if args.command == "negative":
        results = run_negative_probes()
        for r in results:
            marker = "OK" if r.is_pass else "MISMATCH"
            print(f"  {r.scenario}: {r.observed} (expected {r.expected}) {marker}")
        return 0 if all(r.is_pass for r in results) else 1

    if args.command == "receipt":
        paths = emit_receipts(args.out)
        for path in paths.values():
            print(f"wrote {path.relative_to(REPO_ROOT)}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
