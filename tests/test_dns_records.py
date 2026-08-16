"""Live-DNS-path serialization regressions for the SPF/DMARC collector (t28).

``SpfState`` is a frozen slots dataclass, so the live ``_domain_state`` path
must serialize it via ``dataclasses.asdict`` — a direct ``__dict__`` access
raises ``AttributeError`` and the whole DNS envelope degrades to an error.
These tests exercise the exact branch through a fake resolver: the success
path, the per-record resolution-error degradation, and the mixed case.
"""

from __future__ import annotations

from typing import Final

from licenselens.collectors.dns_records import (
    DnsResolutionError,
    TxtResolver,
    collect_dns_evidence,
)

_SPF_STRICT: Final = ("v=spf1 include:spf.protection.outlook.com -all",)
_SPF_NEUTRAL: Final = ("v=spf1 include:spf.protection.outlook.com ?all",)
_DMARC_REJECT: Final = ("v=DMARC1; p=reject; rua=mailto:reports@example.com",)

_VERIFIED_DOMAINS: Final = [
    {"id": "example.com", "isVerified": True},
    {"id": "contoso.onmicrosoft.com", "isVerified": True},
    {"id": "unverified.example.com", "isVerified": False},
]


class _FakeResolver(TxtResolver):
    """Serves fixed TXT tuples per queried name; raises like the real seam."""

    def __init__(self, spf: dict[str, tuple[str, ...]], dmarc: dict[str, tuple[str, ...]]) -> None:
        self._spf = spf
        self._dmarc = dmarc

    def resolve_txt(self, name: str) -> tuple[str, ...]:
        if name.startswith("_dmarc."):
            domain = name[len("_dmarc.") :]
            if domain in self._dmarc:
                return self._dmarc[domain]
        elif name in self._spf:
            return self._spf[name]
        raise DnsResolutionError(name, "NoAnswer")


def test_collect_dns_evidence_serializes_slots_spf_state() -> None:
    """The live success path (previously `spf.__dict__` -> AttributeError)."""
    resolver = _FakeResolver({"example.com": _SPF_STRICT}, {"example.com": _DMARC_REJECT})
    evidence = collect_dns_evidence(_VERIFIED_DOMAINS, resolver)

    assert evidence["domains"] == ["example.com"]
    record = evidence["records"]["example.com"]
    assert record["spf"] == {
        "present": True,
        "hard_fail": True,
        "raw": ["v=spf1 include:spf.protection.outlook.com -all"],
    }
    assert record["dmarc"] == {
        "present": True,
        "policy": "reject",
        "rua": ["reports@example.com"],
        "ruf": [],
        "raw": ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
    }
    assert "error" not in record


def test_collect_dns_evidence_serializes_neutral_and_missing() -> None:
    """A non-rejecting SPF serializes as present-but-not-hard-fail; missing DMARC."""
    resolver = _FakeResolver({"example.com": _SPF_NEUTRAL}, {})
    evidence = collect_dns_evidence(_VERIFIED_DOMAINS, resolver)

    record = evidence["records"]["example.com"]
    assert record["spf"] == {
        "present": True,
        "hard_fail": False,
        "raw": ["v=spf1 include:spf.protection.outlook.com ?all"],
    }
    assert record["dmarc"]["present"] is False
    # A missing DMARC record is surfaced as the resolution reason, per the
    # existing _domain_state contract (the evaluator reads present=False).
    assert record["error"] == "NoAnswer"


def test_collect_dns_evidence_degrades_per_record_on_resolution_error() -> None:
    """Both lookups failing still serialize states (never raise past the seam)."""
    resolver = _FakeResolver({}, {})
    evidence = collect_dns_evidence(_VERIFIED_DOMAINS, resolver)

    record = evidence["records"]["example.com"]
    assert record["spf"]["present"] is False
    assert record["spf"]["hard_fail"] is False
    assert record["spf"]["raw"] == []
    assert record["dmarc"]["present"] is False
    assert record["error"] == "NoAnswer"
