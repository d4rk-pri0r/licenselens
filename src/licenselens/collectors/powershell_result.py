"""Map bounded PowerShell process output to typed EvidenceEnvelope states."""

from __future__ import annotations

import json
import re
from re import Pattern
from typing import Final

from licenselens.collectors.contracts import (
    CollectionMetadata,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
)
from licenselens.collectors.powershell_process import BridgeProcessResult
from licenselens.schema_contracts import JsonValue

BRIDGE_PROTOCOL_VERSION: Final = "1.0"

_SECRET_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    re.compile(
        r"(?i)\b(client_secret|access_token|refresh_token|password|secret|api[_-]?key|token)\b\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+=/]+"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}"),
)


def redact_secrets(text: str, *, extra_secrets: tuple[str, ...] = ()) -> str:
    """Redact credential-shaped substrings from diagnostic text."""
    cleaned = text
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub(_redact_match, cleaned)
    for secret in extra_secrets:
        if secret and secret in cleaned:
            cleaned = cleaned.replace(secret, "***")
    return cleaned


def map_process_result(
    *,
    evidence_key: EvidenceKey,
    result: BridgeProcessResult,
    extra_secrets: tuple[str, ...] = (),
) -> EvidenceEnvelope:
    """Convert a finished bridge process into a typed collection envelope."""
    key = evidence_key
    stderr_text = redact_secrets(
        result.stderr.decode("utf-8", errors="replace"),
        extra_secrets=extra_secrets,
    )
    stdout_text = redact_secrets(
        result.stdout.decode("utf-8", errors="replace"),
        extra_secrets=extra_secrets,
    )

    if result.timed_out:
        return EvidenceEnvelope.error(
            key,
            reason=_diag("powershell bridge timed out", stderr_text),
        )
    if result.stdout_truncated or result.stderr_truncated:
        return EvidenceEnvelope.error(
            key,
            reason=_diag("powershell bridge output exceeded cap", stderr_text),
        )
    if result.exit_code != 0:
        return EvidenceEnvelope.error(
            key,
            reason=_diag(
                f"powershell bridge nonzero exit ({result.exit_code})",
                stderr_text or stdout_text,
            ),
        )

    try:
        parsed = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return EvidenceEnvelope.error(
            key,
            reason=_diag("powershell bridge returned malformed JSON", stderr_text),
        )

    if not isinstance(parsed, dict):
        return EvidenceEnvelope.error(
            key,
            reason="powershell bridge returned malformed JSON (not an object)",
        )

    return _map_parsed_payload(key, parsed, stderr_text=stderr_text)


def _map_parsed_payload(
    key: EvidenceKey,
    parsed: dict[str, JsonValue],
    *,
    stderr_text: str,
) -> EvidenceEnvelope:
    version = parsed.get("protocol_version")
    if version != BRIDGE_PROTOCOL_VERSION:
        return EvidenceEnvelope.error(
            key,
            reason=f"powershell bridge protocol mismatch: {version!r}",
        )

    ok = parsed.get("ok")
    error_obj = parsed.get("error")
    if ok is True and error_obj is None:
        data = parsed.get("data")
        items = 1 if data is not None else 0
        return EvidenceEnvelope(
            key=key,
            health=EvidenceHealth.OK,
            value=data,
            metadata=CollectionMetadata(
                source="powershell.bridge",
                items_collected=items,
            ),
        )

    code, message = _error_fields(error_obj)
    reason = redact_secrets(message or code or "powershell bridge adapter error")
    if stderr_text:
        reason = _diag(reason, stderr_text)

    match code:
        case "denied":
            return EvidenceEnvelope.denied(key, reason=reason)
        case "unsupported_cloud" | "unsupported":
            return EvidenceEnvelope.unsupported(key, reason=reason)
        case "module_missing" | "unavailable":
            return EvidenceEnvelope.unavailable(key, reason=reason)
        case _:
            return EvidenceEnvelope.error(key, reason=reason)


def _error_fields(error_obj: JsonValue) -> tuple[str, str]:
    if not isinstance(error_obj, dict):
        return "", ""
    code_raw = error_obj.get("code")
    msg_raw = error_obj.get("message")
    code = code_raw if isinstance(code_raw, str) else ""
    message = msg_raw if isinstance(msg_raw, str) else ""
    return code, message


def _diag(prefix: str, detail: str) -> str:
    detail = detail.strip()
    if not detail:
        return prefix
    clipped = detail if len(detail) <= 400 else f"{detail[:400]}…"
    return f"{prefix}: {clipped}"


def _redact_match(match: re.Match[str]) -> str:
    text = match.group(0)
    if text.lower().startswith("bearer "):
        return "Bearer ***"
    if "=" in text:
        head, _sep, _tail = text.partition("=")
        return f"{head}=***"
    if ":" in text:
        head, _sep, _tail = text.partition(":")
        return f"{head}:***"
    return "***"
