"""Shared privileged role template IDs and directory role assignment collectors."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

# Well-known privileged directory role template IDs (also used as roleDefinitionId).
PRIVILEGED_ROLE_TEMPLATE_IDS: frozenset[str] = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
        "fdd7a751-b60b-444a-984c-02652fe8fa1c",  # Groups Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",  # Hybrid Identity Administrator
    }
)

# CISA SCuBA highly privileged role set (subset used for phishing-resistant / PIM rules).
HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS: frozenset[str] = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",  # Hybrid Identity Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    }
)

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

ROLE_DISPLAY_NAMES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
}


def is_highly_privileged_role_definition(role_definition_id: str | None) -> bool:
    if not role_definition_id:
        return False
    return role_definition_id.lower() in {r.lower() for r in HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS}


def filter_highly_privileged_assignments(
    assignments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        a
        for a in assignments
        if is_highly_privileged_role_definition(str(a.get("roleDefinitionId") or ""))
    ]


def is_privileged_role_definition(role_definition_id: str | None) -> bool:
    if not role_definition_id:
        return False
    return role_definition_id.lower() in {r.lower() for r in PRIVILEGED_ROLE_TEMPLATE_IDS}


def collect_role_assignments(client: GraphClient) -> list[dict[str, Any]]:
    """Permanent directory role assignments."""
    return client.get_list("/roleManagement/directory/roleAssignments", max_pages=30)


def collect_role_eligibility_schedules(client: GraphClient) -> list[dict[str, Any]]:
    """PIM eligible role schedules (may be empty if PIM unused)."""
    return client.get_list(
        "/roleManagement/directory/roleEligibilitySchedules",
        max_pages=20,
    )


def filter_privileged_assignments(assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        a
        for a in assignments
        if is_privileged_role_definition(str(a.get("roleDefinitionId") or ""))
    ]


def filter_privileged_eligibilities(
    schedules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        s for s in schedules if is_privileged_role_definition(str(s.get("roleDefinitionId") or ""))
    ]


def privileged_principal_ids(assignments: list[dict[str, Any]]) -> set[str]:
    return {
        str(a.get("principalId"))
        for a in filter_privileged_assignments(assignments)
        if a.get("principalId")
    }


# Dry-run demo: standing GA + few eligibilities (PIM not operationalized well)
DEMO_ROLE_ASSIGNMENTS: list[dict[str, Any]] = [
    {
        "id": "asg-1",
        "principalId": "user-admin-1",
        "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE_ID,
        "directoryScopeId": "/",
    },
    {
        "id": "asg-2",
        "principalId": "user-admin-2",
        "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE_ID,
        "directoryScopeId": "/",
    },
    {
        "id": "asg-3",
        "principalId": "user-sec-1",
        "roleDefinitionId": "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "directoryScopeId": "/",
    },
    {
        "id": "asg-4",
        "principalId": "user-help-dormant",
        "roleDefinitionId": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "directoryScopeId": "/",
    },
]

DEMO_ROLE_ELIGIBILITIES: list[dict[str, Any]] = [
    # Intentionally empty / minimal — PIM barely used
]

# Principals who signed in successfully in the lookback (demo)
DEMO_RECENT_SIGNIN_USER_IDS: set[str] = {
    "user-admin-1",
    "user-sec-1",
}

# Enabled directory objects for privileged principals
DEMO_PRINCIPAL_DIRECTORY: dict[str, dict[str, Any]] = {
    "user-admin-1": {
        "id": "user-admin-1",
        "accountEnabled": True,
        "userPrincipalName": "admin1@contoso.com",
        "@odata.type": "#microsoft.graph.user",
    },
    "user-admin-2": {
        "id": "user-admin-2",
        "accountEnabled": True,
        "userPrincipalName": "admin2@contoso.com",
        "@odata.type": "#microsoft.graph.user",
    },
    "user-sec-1": {
        "id": "user-sec-1",
        "accountEnabled": True,
        "userPrincipalName": "sec@contoso.com",
        "@odata.type": "#microsoft.graph.user",
    },
    "user-help-dormant": {
        "id": "user-help-dormant",
        "accountEnabled": True,
        "userPrincipalName": "oldhelp@contoso.com",
        "@odata.type": "#microsoft.graph.user",
    },
}
