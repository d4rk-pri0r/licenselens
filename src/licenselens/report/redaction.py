"""Post-render redaction transform for report outputs.

One shared transform applies the resolved profile's
:class:`~licenselens.config_models.RedactionSettings` to already-rendered text —
HTML, JSON, Markdown, and the bundle's embedded ``DATA_JS``/``VIEWMODEL_JS`` —
replacing the tenant id, any UPN-like string, and the tenant's own domains with
the configured ``replacement`` token. Redaction lives at the report boundary
only: nothing is touched during collection or evaluation, so the same scan
result can be rendered raw (``--no-redact``) or redacted from identical input.

Each value class is gated by its own ``redact_*`` flag under the master
``enabled`` switch, so ``enabled=True`` with ``redact_domains=False`` (the
built-in default) still strips tenant ids and user principal names while
leaving third-party URLs and host names intact.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from licenselens.config_models import RedactionSettings
from licenselens.models import ScanResult

#: One UPN-like string: ``local@domain.tld``. Matches user principal names and
#: email addresses wherever they appear in evidence, summaries, or org
#: metadata. ``*`` is part of the local-part class so the evaluator's
#: already-masked dormant samples (``u***@contoso.onmicrosoft.com``) are still
#: consumed whole — their domain part is tenant data. The lookbehind stops the
#: match from starting mid-token (e.g. inside a URL's userinfo prefix), and the
#: trailing TLD class anchors the domain side.
_UPN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%*'+-])[A-Za-z0-9._%*'+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

#: Left edge of a tenant-domain token. Alphanumerics, ``_`` and ``-`` continue
#: the token; ``.`` deliberately does NOT, so ``portal.contoso.com`` still
#: redacts its ``contoso.com`` tail — a mangled-but-safe ``portal.[redacted]``
#: beats leaking the domain.
_DOMAIN_LEFT_EDGE = r"(?<![A-Za-z0-9_-])"
_DOMAIN_RIGHT_EDGE = r"(?![A-Za-z0-9_-])"

#: Azure subscription GUID as it appears inside an ARM resource id
#: (``/subscriptions/<guid>/...``) — in the scan's workspace scope, in
#: ``observed_resources``, and anywhere evidence embeds an ARM path.
_SUBSCRIPTION_ID_PATTERN = re.compile(
    r"/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)

#: Workspace name: the final path segment of a Log Analytics workspace ARM id.
#: Excludes path separators, quotes, backslashes, and whitespace so a JSON-
#: serialized id ends the match at the closing quote.
_WORKSPACE_NAME_PATTERN = re.compile(r"/workspaces/([^/\"'\\\s]+)")


@dataclass(frozen=True, slots=True)
class RedactionTargets:
    """Literal values a redaction pass must never emit."""

    tenant_ids: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    subscription_ids: tuple[str, ...] = ()
    workspace_names: tuple[str, ...] = ()


def derive_redaction_targets(result: ScanResult) -> RedactionTargets:
    """Harvest tenant identifiers and ARM scope tokens from a scan result.

    The tenant id comes straight from ``result.tenant_id``. Domains are the
    (lower-cased, de-duplicated) domain parts of every UPN-like string in the
    serialized result, so a redacted render cannot leak the tenant's own domain
    through evidence samples or summaries. Third-party domains that never
    appear as a UPN are left untouched. ARM scope tokens — subscription GUIDs
    and workspace names — are harvested from the same serialized dump so an
    Azure-scoped scan cannot leak its resource identifiers either.
    """
    tenant_ids = (result.tenant_id,) if result.tenant_id else ()
    serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=True)
    domains = tuple(
        sorted(
            {
                match.group(0).partition("@")[2].lower()
                for match in _UPN_PATTERN.finditer(serialized)
            }
        )
    )
    subscription_ids = tuple(
        sorted({match.group(1).lower() for match in _SUBSCRIPTION_ID_PATTERN.finditer(serialized)})
    )
    workspace_names = tuple(
        sorted({match.group(1) for match in _WORKSPACE_NAME_PATTERN.finditer(serialized)})
    )
    return RedactionTargets(
        tenant_ids=tenant_ids,
        domains=domains,
        subscription_ids=subscription_ids,
        workspace_names=workspace_names,
    )


def redact_text(
    text: str,
    *,
    targets: RedactionTargets,
    settings: RedactionSettings,
) -> str:
    """Apply one redaction pass to already-rendered text.

    Tenant ids, then UPN-like strings, then tenant domains are replaced with
    ``settings.replacement``, each gated by its ``redact_*`` flag under the
    master ``enabled`` switch. With redaction disabled — or a class's flag off
    — that class passes through unchanged. A callable replacement is used so a
    ``replacement`` token containing backslashes or ``$`` is always literal.
    """
    if not settings.enabled:
        return text
    replacement = settings.replacement

    if settings.redact_tenant_ids:
        for tenant_id in targets.tenant_ids:
            text = re.sub(
                re.escape(tenant_id),
                lambda _match: replacement,
                text,
                flags=re.IGNORECASE,
            )
        for subscription_id in targets.subscription_ids:
            text = re.sub(
                re.escape(subscription_id),
                lambda _match: replacement,
                text,
                flags=re.IGNORECASE,
            )
        for workspace_name in targets.workspace_names:
            text = re.sub(
                _DOMAIN_LEFT_EDGE + re.escape(workspace_name) + _DOMAIN_RIGHT_EDGE,
                lambda _match: replacement,
                text,
                flags=re.IGNORECASE,
            )
    if settings.redact_user_principals:
        text = _UPN_PATTERN.sub(lambda _match: replacement, text)
    if settings.redact_domains:
        for domain in targets.domains:
            text = re.sub(
                _DOMAIN_LEFT_EDGE + re.escape(domain) + _DOMAIN_RIGHT_EDGE,
                lambda _match: replacement,
                text,
                flags=re.IGNORECASE,
            )
    return text


__all__ = ["RedactionTargets", "derive_redaction_targets", "redact_text"]
