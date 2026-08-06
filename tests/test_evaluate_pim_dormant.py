from licenselens.collectors.privileged_roles import (
    DEMO_PRINCIPAL_DIRECTORY,
    DEMO_RECENT_SIGNIN_USER_IDS,
    DEMO_ROLE_ASSIGNMENTS,
    DEMO_ROLE_ELIGIBILITIES,
    GLOBAL_ADMIN_TEMPLATE_ID,
)
from licenselens.engine.evaluate import evaluate_dormant_privileged, evaluate_pim_unused
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


def test_pim_demo_is_gap():
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {
            "role_assignments": DEMO_ROLE_ASSIGNMENTS,
            "role_eligibilities": DEMO_ROLE_ELIGIBILITIES,
        },
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["privileged_permanent_assignments"] >= 1
    assert result.evidence["privileged_eligible_schedules"] == 0


def test_pim_ok_when_eligible_dominates():
    assignments = [
        {
            "principalId": "u1",
            "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE_ID,
        }
    ]
    eligibilities = [
        {"principalId": "u2", "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE_ID},
        {"principalId": "u3", "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE_ID},
    ]
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {"role_assignments": assignments, "role_eligibilities": eligibilities},
    )
    assert result.status == FindingStatus.OK


def test_dormant_demo_finds_unused_admins():
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": DEMO_ROLE_ASSIGNMENTS,
            "recent_signin_user_ids": DEMO_RECENT_SIGNIN_USER_IDS,
            "principal_directory": DEMO_PRINCIPAL_DIRECTORY,
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status in {FindingStatus.GAP, FindingStatus.PARTIAL}
    assert result.evidence["dormant_privileged_users"] >= 1
    # Redacted UPNs should not expose full local-part beyond first char
    for row in result.evidence["dormant_sample"]:
        upn = row["userPrincipalName"]
        if "@" in upn:
            assert "***@" in upn


def test_dormant_ok_when_all_active():
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": DEMO_ROLE_ASSIGNMENTS,
            "recent_signin_user_ids": {
                "user-admin-1",
                "user-admin-2",
                "user-sec-1",
                "user-help-dormant",
            },
            "principal_directory": DEMO_PRINCIPAL_DIRECTORY,
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["dormant_privileged_users"] == 0
