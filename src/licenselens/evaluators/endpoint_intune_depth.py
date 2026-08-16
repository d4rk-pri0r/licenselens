"""Deep endpoint evaluators (Todo 17): ASR rules, BitLocker, tamper
protection, compliance enforcement state, and MAM app protection.

Every check here distinguishes "configured" from "assigned/enforced" — a
policy that merely exists never satisfies any of them.
"""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.endpoint_lib import (
    app_protection_policies,
    asr_policies,
    compliance_policies,
    compliance_state_summary,
    device_configurations,
    direct_meta,
    intune_bundle,
    surface_error,
    tamper_device_state,
    unavailable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_endpoint_asr_rules",
    "evaluate_endpoint_bitlocker_policy",
    "evaluate_endpoint_compliance_enforcement",
    "evaluate_endpoint_mam_app_protection",
    "evaluate_endpoint_tamper_protection",
]


def evaluate_endpoint_asr_rules(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """ASR policies exist, are assigned, and actually carry rules."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "asr_policies")
    if error:
        return unavailable(
            "Attack-surface-reduction policies could not be read; treated as unresolved.",
            surface="asr_policies",
            customer_summary="We could not confirm whether ASR rules are configured and enforced.",
        )
    policies = asr_policies(bundle)
    evidence_out = {
        "asr_policy_count": len(policies),
        "assigned_count": sum(1 for p in policies if p.get("assigned")),
    }
    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No attack-surface-reduction policy is configured.",
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for endpoint protection, but no ASR policy is configured, "
                "so ransomware-style behavior is not blocked."
            ),
            **direct_meta(),
        )
    if any(p.get("assignments_error") for p in policies):
        evidence_out["assignment_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(policies)} ASR policy(ies) defined, but assignment details "
                "could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "ASR policies exist, but we could not confirm they are assigned to devices."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["ASR assignments were not readable; verify in the Intune admin center."],
        )
    assigned = [p for p in policies if p.get("assigned")]
    evidence_out["assigned_count"] = len(assigned)
    if not assigned:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{len(policies)} ASR policy(ies) defined but none are assigned.",
            evidence=evidence_out,
            customer_summary=(
                "ASR policies exist but are not assigned, so no attack surface reduction "
                "rules are enforced on devices."
            ),
            **direct_meta(),
        )
    if any(p.get("rules_error") for p in assigned):
        evidence_out["rules_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(assigned)} ASR policy(ies) assigned, but rule details could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "ASR policies are assigned, but we could not confirm they carry real rules."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["ASR rule detail was not readable; verify in the Intune admin center."],
        )
    with_rules = [p for p in assigned if int(p.get("rule_count") or 0) > 0]
    evidence_out["rules_total"] = sum(int(p.get("rule_count") or 0) for p in assigned)
    if not with_rules:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"{len(assigned)} ASR policy(ies) assigned but none configure any rules.",
            evidence=evidence_out,
            customer_summary=(
                "ASR policies are assigned, but they are empty shells with no rules inside."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["Assigned ASR policies carry no attack surface reduction rules."],
        )
    if len(with_rules) < len(assigned):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Only {len(with_rules)} of {len(assigned)} assigned ASR policy(ies) "
                "configure any rules."
            ),
            evidence=evidence_out,
            customer_summary="Some assigned ASR policies carry no attack surface reduction rules.",
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["Not every assigned ASR policy configures rules."],
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            f"{len(assigned)} ASR policy(ies) assigned with "
            f"{evidence_out['rules_total']} rule(s) configured."
        ),
        evidence=evidence_out,
        customer_summary="Attack surface reduction rules are configured and enforced.",
        **direct_meta(),
    )


def evaluate_endpoint_bitlocker_policy(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """A BitLocker/disk-encryption device configuration exists and is assigned."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "device_configurations")
    if error:
        return unavailable(
            "Intune device configurations could not be read; treated as unresolved.",
            surface="device_configurations",
            customer_summary="We could not confirm whether an encryption policy is applied.",
        )
    configs = [c for c in device_configurations(bundle) if _is_bitlocker_config(c)]
    evidence_out = {"bitlocker_config_count": len(configs)}
    if not configs:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No BitLocker or disk-encryption device configuration is defined.",
            evidence=evidence_out,
            customer_summary=(
                "No encryption policy is configured, so lost or stolen devices may leak work data."
            ),
            **direct_meta(),
        )
    if any(c.get("assignments_error") for c in configs):
        evidence_out["assignment_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(configs)} encryption configuration(s) defined, but assignment "
                "details could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "An encryption policy exists, but we could not confirm it is assigned to devices."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[
                "Encryption policy assignments were not readable; "
                "verify in the Intune admin center."
            ],
        )
    assigned = [c for c in configs if c.get("assigned")]
    evidence_out["assigned_count"] = len(assigned)
    if not assigned:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{len(configs)} encryption configuration(s) defined but none are assigned.",
            evidence=evidence_out,
            customer_summary=(
                "An encryption policy exists but is not assigned, "
                "so devices are not being encrypted."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{len(assigned)} encryption configuration(s) assigned to devices.",
        evidence=evidence_out,
        customer_summary="A drive-encryption policy is configured and assigned.",
        **direct_meta(),
    )


def evaluate_endpoint_tamper_protection(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Defender ATP config assigned and tamper protection enabled on devices."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "device_configurations")
    if error:
        return unavailable(
            "Intune device configurations could not be read; treated as unresolved.",
            surface="device_configurations",
            customer_summary="We could not confirm whether tamper protection is enforced.",
        )
    configs = [c for c in device_configurations(bundle) if _is_defender_atp_config(c)]
    state = tamper_device_state(bundle)
    enabled = _int_field(state, "enabled")
    disabled = _int_field(state, "disabled")
    unknown = _int_field(state, "unknown")
    sampled = _int_field(state, "sampled")
    evidence_out = {
        "defender_atp_config_count": len(configs),
        "assigned_count": sum(1 for c in configs if c.get("assigned")),
        "sampled_devices": sampled,
        "tamper_enabled_devices": enabled,
        "tamper_disabled_devices": disabled,
        "tamper_unknown_devices": unknown,
    }
    if any(c.get("assignments_error") for c in configs):
        evidence_out["assignment_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(configs)} Defender ATP configuration(s) defined, but assignment "
                "details could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "A Defender ATP configuration exists, but we could not confirm it is assigned."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[
                "Defender ATP assignments were not readable; verify in the Intune admin center."
            ],
        )
    assigned = [c for c in configs if c.get("assigned")]
    evidence_out["assigned_count"] = len(assigned)
    if not assigned:
        if enabled and not disabled:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    "No Defender ATP configuration is assigned, though sampled devices "
                    "report tamper protection enabled."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Devices show tamper protection on, but no assigned policy manages it."
                ),
                confidence=Confidence.MEDIUM,
                data_sources=["graph.deviceManagement"],
                limitations=[
                    "Tamper protection is enabled on devices but not managed by an assigned policy."
                ],
            )
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Defender ATP tamper-protection configuration is assigned to devices.",
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for endpoint protection, but tamper protection is "
                "not configured or enforced."
            ),
            **direct_meta(),
        )
    if disabled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Tamper protection is assigned but disabled on {disabled} sampled device(s)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "The policy is assigned, but some devices have tamper protection turned off."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[f"{disabled} sampled device(s) report tamper protection disabled."],
        )
    if enabled:
        meta = direct_meta()
        if unknown:
            meta["limitations"] = [f"{unknown} sampled device(s) did not report tamper state."]
        return Evaluation(
            status=FindingStatus.OK,
            summary="Tamper protection is assigned and enabled on sampled devices.",
            evidence=evidence_out,
            customer_summary="Defender tamper protection is configured and enforced.",
            **meta,
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="Tamper protection is assigned, but no sampled device confirms it is enabled.",
        evidence=evidence_out,
        customer_summary=(
            "The policy is assigned, but we could not confirm any device has it enabled yet."
        ),
        confidence=Confidence.MEDIUM,
        data_sources=["graph.deviceManagement"],
        limitations=["No sampled Windows device reported tamper protection state."],
    )


def evaluate_endpoint_compliance_enforcement(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Managed devices are actually compliant, not just covered by a policy."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "compliance_state_summary")
    if error:
        return unavailable(
            "Device-compliance state could not be read; treated as unresolved.",
            surface="compliance_state_summary",
            customer_summary="We could not confirm whether devices are actually compliant.",
        )
    summary = compliance_state_summary(bundle)
    if summary is None:
        return unavailable(
            "Device-compliance state summary was not returned.",
            surface="compliance_state_summary",
            customer_summary="We could not confirm whether devices are actually compliant.",
        )
    compliant = _int_field(summary, "compliantDeviceCount")
    noncompliant = _int_field(summary, "nonCompliantDeviceCount")
    unknown = _int_field(summary, "unknownDeviceCount")
    error_count = _int_field(summary, "errorDeviceCount")
    conflict = _int_field(summary, "conflictDeviceCount")
    in_grace = _int_field(summary, "inGracePeriodCount")
    managed = compliant + noncompliant + unknown + error_count + conflict + in_grace
    evidence_out = {
        "compliance_policy_count": len(compliance_policies(bundle)),
        "managed_devices_total": managed,
        "compliant_devices": compliant,
        "noncompliant_devices": noncompliant,
        "unknown_devices": unknown,
        "error_devices": error_count,
        "conflict_devices": conflict,
        "in_grace_period_devices": in_grace,
    }
    if managed == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No device-compliance state has been reported for managed devices.",
            evidence=evidence_out,
            customer_summary=(
                "We found no reported compliance state, so enforcement cannot be confirmed."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["No managed device compliance state was reported."],
        )
    if compliant == 0:
        if noncompliant:
            return Evaluation(
                status=FindingStatus.GAP,
                summary=f"No devices are compliant; {noncompliant} are noncompliant.",
                evidence=evidence_out,
                customer_summary=(
                    "Compliance policies are not translating into compliant devices."
                ),
                **direct_meta(),
            )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Compliance state is reported, but no device is confirmed compliant.",
            evidence=evidence_out,
            customer_summary=(
                "We could not confirm any compliant device, so enforcement is unproven."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["No device is confirmed compliant in the reported state."],
        )
    if noncompliant:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"{noncompliant} managed device(s) are noncompliant despite policies.",
            evidence=evidence_out,
            customer_summary=(
                "Most devices comply, but some are noncompliant and still need remediation."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[f"{noncompliant} device(s) remain noncompliant."],
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{compliant} device(s) are compliant with zero noncompliant devices.",
        evidence=evidence_out,
        customer_summary="Devices are actually compliant, so the compliance gate is enforced.",
        **direct_meta(),
    )


def evaluate_endpoint_mam_app_protection(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """App protection policies exist and are assigned (or org-wide defaults)."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "app_protection_policies")
    if error:
        return unavailable(
            "App protection policies could not be read; treated as unresolved.",
            surface="app_protection_policies",
            customer_summary="We could not confirm whether app data is protected on devices.",
        )
    policies = app_protection_policies(bundle)
    evidence_out = {
        "app_protection_policy_count": len(policies),
        "assigned_count": sum(1 for p in policies if p.get("assigned")),
    }
    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No MAM app-protection policies are configured.",
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for device management, but no app protection policy "
                "guards work data on phones and apps."
            ),
            **direct_meta(),
        )
    if any(p.get("assignments_error") for p in policies):
        evidence_out["assignment_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(policies)} app-protection policy(ies) defined, but assignment "
                "details could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "App protection policies exist, but we could not confirm they are assigned."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[
                "App protection assignments were not readable; verify in the Intune admin center."
            ],
        )
    assigned = [p for p in policies if p.get("assigned")]
    evidence_out["assigned_count"] = len(assigned)
    if not assigned:
        if any(p.get("assignment_mode") == "unknown" for p in policies):
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"{len(policies)} app-protection policy(ies) defined, but their "
                    "assignment could not be determined."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "App protection policies exist, but we could not tell whether they apply."
                ),
                confidence=Confidence.MEDIUM,
                data_sources=["graph.deviceManagement"],
                limitations=["Assignment semantics of some app protection policies are unknown."],
            )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{len(policies)} app-protection policy(ies) defined but none are assigned.",
            evidence=evidence_out,
            customer_summary=(
                "App protection policies exist but are not assigned, so they protect nothing."
            ),
            **direct_meta(),
        )
    evidence_out["org_wide_count"] = sum(
        1 for p in policies if p.get("assignment_mode") == "default"
    )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{len(assigned)} app-protection policy(ies) assigned or org-wide.",
        evidence=evidence_out,
        customer_summary="App protection policies are configured and assigned.",
        **direct_meta(),
    )


def _is_bitlocker_config(config: dict[str, Any]) -> bool:
    odata = str(config.get("odata_type") or config.get("@odata.type") or "").lower()
    name = str(config.get("displayName") or "").lower()
    if "bitlocker" in f"{odata} {name}":
        return True
    if "disk encryption" in name or "diskencryption" in odata:
        return True
    if "windows10endpointprotectionconfiguration" in odata:
        return bool(config.get("bitLockerEncryptDevice"))
    return False


def _is_defender_atp_config(config: dict[str, Any]) -> bool:
    odata = str(config.get("odata_type") or config.get("@odata.type") or "").lower()
    return "windowsdefenderadvancedthreatprotectionconfiguration" in odata


def _int_field(mapping: dict[str, Any], name: str) -> int:
    value = mapping.get(name)
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0
