"""WS3-C: KQL table-ref tokenizer."""

from __future__ import annotations

from pathlib import Path

from licenselens.kql.table_refs import extract_table_refs

KNOWN = frozenset(
    {
        "SigninLogs",
        "AuditLogs",
        "DeviceProcessEvents",
        "EmailEvents",
        "SecurityAlert",
        "OfficeActivity",
    }
)
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "kql"


def test_fifteen_fixtures_match_headers() -> None:
    files = sorted(FIXTURE_DIR.glob("*.kql"))
    assert len(files) == 15
    for path in files:
        expected_tables: set[str] = set()
        expected_parsers: set[str] = set()
        expected_indet = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("# Expected tables:"):
                rest = line.split(":", 1)[1].strip()
                expected_tables = {part.strip() for part in rest.split(",") if part.strip()}
            elif line.startswith("# Expected parsers:"):
                rest = line.split(":", 1)[1].strip()
                expected_parsers = {part.strip() for part in rest.split(",") if part.strip()}
            elif line.startswith("# Expected indeterminate:"):
                expected_indet = line.split(":", 1)[1].strip().lower() == "true"
        body = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#")
        )
        refs = extract_table_refs(body, known_tables=KNOWN)
        assert refs.tables == frozenset(expected_tables), path.name
        assert refs.parsers == frozenset(expected_parsers), path.name
        assert refs.indeterminate is expected_indet, path.name


def test_empty_query_is_indeterminate() -> None:
    refs = extract_table_refs("   \n", known_tables=KNOWN)
    assert refs.indeterminate is True
    assert not refs.tables
    assert not refs.parsers


def test_asim_dns_parser_prefix() -> None:
    refs = extract_table_refs("_ASim_Dns | take 1", known_tables=KNOWN)
    assert refs.parsers == frozenset({"_ASim_Dns"})
    assert refs.indeterminate is False


def test_custom_cl_table_is_parser() -> None:
    refs = extract_table_refs("Foo_CL | take 1", known_tables=KNOWN)
    assert refs.parsers == frozenset({"Foo_CL"})
    assert refs.indeterminate is False


def test_unbound_ident_is_indeterminate() -> None:
    refs = extract_table_refs("NotAKnownTable | take 1", known_tables=KNOWN)
    assert refs.indeterminate is True


def test_externaldata_is_not_a_table() -> None:
    refs = extract_table_refs(
        'externaldata(col:string)["https://example.invalid"]',
        known_tables=KNOWN,
    )
    assert not refs.tables
    assert refs.indeterminate is False


def test_range_is_not_a_table() -> None:
    refs = extract_table_refs("range x from 1 to 10 step 1", known_tables=KNOWN)
    assert not refs.tables
    assert refs.indeterminate is False


def test_join_kind_inner() -> None:
    refs = extract_table_refs(
        "SigninLogs | join kind=inner (AuditLogs) on UserId",
        known_tables=KNOWN,
    )
    assert refs.tables == frozenset({"SigninLogs", "AuditLogs"})
    assert refs.indeterminate is False


def test_table_function_is_indeterminate() -> None:
    refs = extract_table_refs(
        'let t = "SigninLogs"; table(t) | take 1',
        known_tables=KNOWN,
    )
    assert refs.indeterminate is True


def test_string_containing_table_name_is_ignored() -> None:
    refs = extract_table_refs(
        'SigninLogs | where UserPrincipalName == "SigninLogs"',
        known_tables=KNOWN,
    )
    assert refs.tables == frozenset({"SigninLogs"})
    assert refs.indeterminate is False
