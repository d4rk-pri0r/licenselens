"""Bounded DNS TXT resolution for email-authentication checks (SPF / DMARC).

The resolver is an injectable seam so evaluators and tests never touch the
network. The production resolver uses the system-configured DNS servers via
``dnspython`` (no external SaaS, no hard-coded public resolver), with a hard
lifetime bound and per-query timeout. Dry-run evidence is a checked-in fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Protocol

from licenselens.schema_contracts import JsonValue

DEFAULT_DNS_TIMEOUT_SECONDS: Final = 8.0
DEFAULT_DNS_LIFETIME_SECONDS: Final = 10.0

_MULTI_LABEL_TLDS: Final = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "me.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "gov.au",
        "com.br",
        "com.cn",
        "com.mx",
        "co.jp",
        "co.nz",
        "co.za",
        "com.sg",
        "com.tr",
        "com.ar",
        "com.co",
    }
)

_DMARC_PREFIX: Final = "_dmarc."


class DnsResolutionError(Exception):
    """A TXT lookup failed or timed out for a domain."""

    def __init__(self, domain: str, reason: str) -> None:
        self.domain = domain
        self.reason = reason
        super().__init__(f"DNS lookup failed for {domain}: {reason}")


class TxtResolver(Protocol):
    def resolve_txt(self, name: str) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class SpfState:
    present: bool
    hard_fail: bool
    raw: tuple[str, ...] = ()

    @property
    def compliant(self) -> bool:
        return self.present and self.hard_fail


@dataclass(frozen=True, slots=True)
class DmarcState:
    present: bool
    policy: str = "none"
    rua: tuple[str, ...] = ()
    ruf: tuple[str, ...] = ()
    raw: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DomainDnsState:
    domain: str
    spf: SpfState
    dmarc: DmarcState
    error: str | None = None


def system_resolver() -> TxtResolver:
    """Build the dnspython-backed resolver with bounded lifetime/timeout."""
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 3.0
    resolver.lifetime = DEFAULT_DNS_LIFETIME_SECONDS
    return _DnspythonTxtResolver(resolver)


class _DnspythonTxtResolver:
    def __init__(self, resolver: object) -> None:
        self._resolver = resolver

    def resolve_txt(self, name: str) -> tuple[str, ...]:
        import dns.resolver

        try:
            answer = self._resolver.resolve(name, "TXT")  # type: ignore[attr-defined]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ) as exc:
            raise DnsResolutionError(name, type(exc).__name__) from exc
        records: list[str] = []
        for rdataset in answer:
            for record in rdataset:
                records.append("".join(part.decode("utf-8", "replace") for part in record.strings))
        return tuple(records)


def registrable_domains(domains: list[dict[str, object]]) -> list[str]:
    """Return verified, tenant-owned registrable domains for DNS checks.

    Skips Microsoft-managed ``*.onmicrosoft.com`` names and any unverified
    domain; a tenant cannot publish SPF/DMARC for those, so they are not gaps.
    """
    result: list[str] = []
    for domain in domains:
        name = str(domain.get("id") or "").strip().lower().rstrip(".")
        if not name:
            continue
        if name.endswith(".onmicrosoft.com"):
            continue
        if domain.get("isVerified") is not True:
            continue
        registrable = _registrable(name)
        if registrable and registrable not in result:
            result.append(registrable)
    return sorted(result)


def _registrable(name: str) -> str:
    labels = name.split(".")
    if len(labels) < 2:
        return name
    if f"{labels[-2]}.{labels[-1]}" in _MULTI_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_spf(txts: tuple[str, ...]) -> SpfState:
    """Classify SPF TXT records; hard-fail requires a ``-all``/``~all`` tail."""
    raw = tuple(txt for txt in txts if txt.strip().lower().startswith("v=spf1"))
    if not raw:
        return SpfState(present=False, hard_fail=False, raw=())
    lowered = raw[0].lower()
    hard = lowered.rstrip().endswith("-all") or lowered.rstrip().endswith("~all")
    return SpfState(present=True, hard_fail=hard, raw=raw)


def parse_dmarc(txts: tuple[str, ...]) -> DmarcState:
    """Classify the DMARC TXT record at ``_dmarc.<domain>``."""
    raw = tuple(txt for txt in txts if txt.strip().lower().startswith("v=dmarc1"))
    if not raw:
        return DmarcState(present=False, raw=())
    record = raw[0]
    policy = "none"
    rua: list[str] = []
    ruf: list[str] = []
    for token in record.split(";"):
        token = token.strip()
        key, _, value = token.partition("=")
        key = key.strip().lower()
        if key == "p" and value.strip():
            policy = value.strip().lower()
        elif key == "rua" and value.strip():
            rua.extend(_mailtos(value))
        elif key == "ruf" and value.strip():
            ruf.extend(_mailtos(value))
    return DmarcState(present=True, policy=policy, rua=tuple(rua), ruf=tuple(ruf), raw=raw)


def _mailtos(value: str) -> list[str]:
    result: list[str] = []
    for entry in value.split(","):
        entry = entry.strip()
        if entry.lower().startswith("mailto:"):
            address = entry[len("mailto:") :].strip()
            if address:
                result.append(address.lower())
    return result


def collect_dns_evidence(
    domains: list[dict[str, object]],
    resolver: TxtResolver,
) -> dict[str, JsonValue]:
    """Resolve SPF/DMARC TXT records for each registrable domain (bounded)."""
    records: dict[str, JsonValue] = {}
    for domain in registrable_domains(domains):
        records[domain] = _domain_state(domain, resolver)
    return {"domains": sorted(records), "records": records}


def _domain_state(domain: str, resolver: TxtResolver) -> dict[str, JsonValue]:
    state: dict[str, JsonValue] = {"domain": domain}
    try:
        spf = parse_spf(resolver.resolve_txt(domain))
    except DnsResolutionError as exc:
        spf = SpfState(present=False, hard_fail=False)
        state["error"] = exc.reason
    try:
        dmarc = parse_dmarc(resolver.resolve_txt(_DMARC_PREFIX + domain))
    except DnsResolutionError as exc:
        dmarc = DmarcState(present=False)
        state["error"] = state.get("error") or exc.reason
    state["spf"] = spf.__dict__
    state["dmarc"] = dmarc.__dict__
    return state


DEMO_DNS_RECORDS: Final[dict[str, JsonValue]] = {
    "domains": ["contoso.com"],
    "records": {
        "contoso.com": {
            "domain": "contoso.com",
            "spf": {
                "present": True,
                "hard_fail": True,
                "raw": ["v=spf1 include:spf.protection.outlook.com -all"],
            },
            "dmarc": {
                "present": True,
                "policy": "reject",
                "rua": ["reports@contoso.com"],
                "ruf": ["reports@contoso.com"],
                "raw": ["v=DMARC1; p=reject; rua=mailto:reports@contoso.com"],
            },
            "error": None,
        }
    },
}
