"""Parse Maester JSON exports and map SCuBA-tagged tests onto LicenseLens checks.

Fields used from ``Invoke-Maester -OutputJson`` (pinned contract):

* ``Tests[].Name``
* ``Tests[].Result``
* ``Tests[].Tag`` (string or list)
* ``Tests[].ResultDetail.TestResult`` (optional prose)

External results are a side artifact. They are never merged into ``findings[]``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from licenselens.catalog.coverage import scuba_policy_map
from licenselens.models import Finding, FindingStatus, ScanResult
from licenselens.schema_contracts import EvaluationMode

SCUBA_ID_PATTERN = re.compile(r"MS\.[A-Z]+\.\d+\.\d+v\d+")

OWNED_FAILURE_VERDICT = "You pay for the capability this test covers; Maester confirms the gap"
NOT_OWNED_FAILURE_VERDICT = (
    "Maester flags this, but the enabling SKU is not detected — this is a "
    "licensing decision, not a configuration gap"
)

_FAIL = frozenset({"failed", "fail", "false", "notpassed"})
_PASS = frozenset({"passed", "pass", "true", "ok"})


class MaesterParseError(ValueError):
    """The Maester JSON export is missing required fields or is malformed."""


@dataclass(frozen=True, slots=True)
class MaesterTest:
    name: str
    result: str
    tags: tuple[str, ...]
    scuba_ids: tuple[str, ...]
    test_result: str = ""

    @property
    def failed(self) -> bool:
        return _normalize_result(self.result) == "failed"

    @property
    def passed(self) -> bool:
        return _normalize_result(self.result) == "passed"


@dataclass(frozen=True, slots=True)
class MappedFailure:
    maester_name: str
    scuba_id: str
    check_id: str
    our_status: str
    entitlement: str
    verdict: str
    evaluation_mode: str = EvaluationMode.EXTERNAL.value


@dataclass(frozen=True, slots=True)
class Disagreement:
    check_id: str
    kind: str
    maester_name: str
    maester_result: str
    our_status: str


@dataclass(frozen=True, slots=True)
class MaesterIngestReport:
    mapped_failures: tuple[MappedFailure, ...]
    unmapped: tuple[str, ...]
    disagreements: tuple[Disagreement, ...]
    evaluation_mode: str = EvaluationMode.EXTERNAL.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluation_mode": self.evaluation_mode,
            "mapped_failures": [
                {
                    "maester_name": row.maester_name,
                    "scuba_id": row.scuba_id,
                    "check_id": row.check_id,
                    "our_status": row.our_status,
                    "entitlement": row.entitlement,
                    "verdict": row.verdict,
                }
                for row in self.mapped_failures
            ],
            "unmapped": list(self.unmapped),
            "disagreements": [
                {
                    "check_id": row.check_id,
                    "kind": row.kind,
                    "maester_name": row.maester_name,
                    "maester_result": row.maester_result,
                    "our_status": row.our_status,
                }
                for row in self.disagreements
            ],
        }


def parse_maester_results(path: Path) -> list[MaesterTest]:
    """Parse a Maester ``Invoke-Maester -OutputJson`` export."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaesterParseError(f"invalid Maester JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise MaesterParseError("Maester JSON root must be an object")
    tests = raw.get("Tests")
    if not isinstance(tests, list):
        raise MaesterParseError("Maester JSON missing Tests list")
    parsed: list[MaesterTest] = []
    for index, item in enumerate(tests):
        if not isinstance(item, dict):
            raise MaesterParseError(f"Tests[{index}] is not an object")
        name = str(item.get("Name") or "").strip()
        if not name:
            raise MaesterParseError(f"Tests[{index}] missing Name")
        result = str(item.get("Result") or "").strip()
        tags = _as_tags(item.get("Tag"))
        detail = item.get("ResultDetail")
        test_result = ""
        if isinstance(detail, dict):
            test_result = str(detail.get("TestResult") or "").strip()
        scuba = tuple(_scuba_ids_from(name, tags, test_result))
        parsed.append(
            MaesterTest(
                name=name,
                result=result,
                tags=tuple(tags),
                scuba_ids=scuba,
                test_result=test_result,
            )
        )
    return parsed


def ingest_maester(
    tests: list[MaesterTest],
    scan: ScanResult,
    *,
    policy_map: dict[str, tuple[str, ...]] | None = None,
) -> MaesterIngestReport:
    """Map Maester tests onto a LicenseLens scan. Never mutates ``scan.findings``."""
    mapping = policy_map if policy_map is not None else scuba_policy_map()
    by_id = {finding.check_id: finding for finding in scan.findings}
    owned = set(scan.owned_capabilities)
    mapped_failures: list[MappedFailure] = []
    unmapped: list[str] = []
    disagreements: list[Disagreement] = []
    seen_unmapped: set[str] = set()

    for test in tests:
        check_ids = _local_checks_for(test, mapping)
        if not check_ids:
            if test.name not in seen_unmapped:
                unmapped.append(test.name)
                seen_unmapped.add(test.name)
            continue
        for scuba_id, check_id in check_ids:
            finding = by_id.get(check_id)
            our_status = finding.status.value if finding is not None else "missing"
            if test.failed:
                entitlement, verdict = _entitlement_verdict(finding, owned)
                mapped_failures.append(
                    MappedFailure(
                        maester_name=test.name,
                        scuba_id=scuba_id,
                        check_id=check_id,
                        our_status=our_status,
                        entitlement=entitlement,
                        verdict=verdict,
                    )
                )
                if our_status == FindingStatus.OK.value:
                    disagreements.append(
                        Disagreement(
                            check_id=check_id,
                            kind="maester_fail_ours_ok",
                            maester_name=test.name,
                            maester_result=test.result,
                            our_status=our_status,
                        )
                    )
            elif test.passed and our_status == FindingStatus.GAP.value:
                disagreements.append(
                    Disagreement(
                        check_id=check_id,
                        kind="ours_gap_maester_pass",
                        maester_name=test.name,
                        maester_result=test.result,
                        our_status=our_status,
                    )
                )

    mapped_failures.sort(key=lambda row: (row.check_id, row.maester_name, row.scuba_id))
    disagreements.sort(key=lambda row: (row.kind, row.check_id, row.maester_name))
    return MaesterIngestReport(
        mapped_failures=tuple(mapped_failures),
        unmapped=tuple(sorted(unmapped)),
        disagreements=tuple(disagreements),
    )


def render_maester_json(report: MaesterIngestReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def render_maester_markdown(report: MaesterIngestReport) -> str:
    lines = [
        "# Maester ingest",
        "",
        "Use Maester for deep configuration testing; use LicenseLens to know",
        "which failures you are paying to fix. These rows are a side artifact",
        "and are not merged into the main findings list.",
        "",
        f"- Evaluation mode: `{report.evaluation_mode}`",
        f"- Mapped Maester failures: {len(report.mapped_failures)}",
        f"- Unmapped tests: {len(report.unmapped)}",
        f"- Disagreements: {len(report.disagreements)}",
        "",
        "## Mapped failures",
        "",
    ]
    if not report.mapped_failures:
        lines.append("_None._")
        lines.append("")
    else:
        lines.append(
            "| Maester test | SCuBA | LicenseLens check | Our status | Entitlement | Verdict |"
        )
        lines.append("|---|---|---|---|---|---|")
        for row in report.mapped_failures:
            lines.append(
                f"| {row.maester_name} | `{row.scuba_id}` | `{row.check_id}` | "
                f"{row.our_status} | {row.entitlement} | {row.verdict} |"
            )
        lines.append("")
    lines.extend(["## Unmapped", ""])
    if not report.unmapped:
        lines.append("_None._")
        lines.append("")
    else:
        for name in report.unmapped:
            lines.append(f"- {name}")
        lines.append("")
    lines.extend(["## Disagreements", ""])
    if not report.disagreements:
        lines.append("_None._")
        lines.append("")
    else:
        lines.append("| Kind | Check | Maester test | Maester | Ours |")
        lines.append("|---|---|---|---|---|")
        for row in report.disagreements:
            lines.append(
                f"| {row.kind} | `{row.check_id}` | {row.maester_name} | "
                f"{row.maester_result} | {row.our_status} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_maester_ingest(
    report: MaesterIngestReport,
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "security-license-lens-external-maester.json"
    md_path = output_dir / "security-license-lens-external-maester.md"
    json_path.write_text(render_maester_json(report), encoding="utf-8")
    md_path.write_text(render_maester_markdown(report), encoding="utf-8")
    return json_path, md_path


def _as_tags(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [part.strip() for part in re.split(r"[,\s]+", raw) if part.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return [str(raw).strip()]


def _scuba_ids_from(*blobs: object) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        if isinstance(blob, (list, tuple)):
            text = " ".join(str(item) for item in blob)
        else:
            text = str(blob or "")
        for match in SCUBA_ID_PATTERN.findall(text):
            if match not in seen:
                seen.add(match)
                found.append(match)
    return found


def _local_checks_for(
    test: MaesterTest,
    mapping: dict[str, tuple[str, ...]],
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for scuba_id in test.scuba_ids:
        for check_id in mapping.get(scuba_id, ()):
            key = (scuba_id, check_id)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def _normalize_result(result: str) -> str:
    key = result.strip().lower().replace(" ", "")
    if key in _FAIL:
        return "failed"
    if key in _PASS:
        return "passed"
    return key


def _entitlement_verdict(
    finding: Finding | None,
    owned: set[str],
) -> tuple[str, str]:
    if finding is None:
        return "unknown", NOT_OWNED_FAILURE_VERDICT
    if finding.status is FindingStatus.NOT_LICENSED:
        return "not_licensed", NOT_OWNED_FAILURE_VERDICT
    used = set(finding.entitlements_used)
    if used & owned or finding.status is not FindingStatus.NOT_LICENSED:
        return "owned", OWNED_FAILURE_VERDICT
    return "unknown", NOT_OWNED_FAILURE_VERDICT
