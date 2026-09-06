"""KQL table-reference extraction (pure, no I/O)."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["TableRefs", "extract_table_refs"]

_PARSER_PREFIXES = ("_Im_", "_ASim_", "ASim", "im")
_NO_TABLE_COMMANDS = frozenset({"externaldata", "datatable", "print", "range"})
_JOIN_KINDS = frozenset(
    {
        "inner",
        "leftouter",
        "rightouter",
        "fullouter",
        "leftanti",
        "rightanti",
        "leftsemi",
        "rightsemi",
    }
)


@dataclass(frozen=True, slots=True)
class TableRefs:
    tables: frozenset[str]
    parsers: frozenset[str]
    indeterminate: bool


def extract_table_refs(query: str, *, known_tables: frozenset[str]) -> TableRefs:
    """Return table/parser refs found at tabular-expression positions.

    Conservative: unknown identifiers at a table position, ``union *``,
    ``table()`` dynamic arguments, and empty queries are indeterminate.
    Indeterminate rules must never be counted dead by the parity evaluator.
    """
    stripped = _strip_comments_and_strings(query)
    if not stripped.strip():
        return TableRefs(tables=frozenset(), parsers=frozenset(), indeterminate=True)

    tables: set[str] = set()
    parsers: set[str] = set()
    indeterminate = False
    let_bindings: dict[str, str] = {}

    for statement in _split_statements(stripped):
        stmt_tables, stmt_parsers, stmt_indet, let_bindings = _scan_statement(
            statement, known_tables=known_tables, let_bindings=let_bindings
        )
        tables.update(stmt_tables)
        parsers.update(stmt_parsers)
        indeterminate = indeterminate or stmt_indet

    return TableRefs(
        tables=frozenset(tables),
        parsers=frozenset(parsers),
        indeterminate=indeterminate,
    )


def _strip_comments_and_strings(query: str) -> str:
    out: list[str] = []
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        nxt = query[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and query[i] not in "\n\r":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n - 1 and not (query[i] == "*" and query[i + 1] == "/"):
                i += 1
            i = min(n, i + 2)
            continue
        if ch in {'"', "'"}:
            quote = ch
            i += 1
            while i < n:
                if query[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if query[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _split_statements(text: str) -> list[str]:
    return [part.strip() for part in text.split(";") if part.strip()]


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isalnum() or ch == "_":
            buf.append(ch)
            i += 1
            continue
        if buf:
            tokens.append("".join(buf))
            buf = []
        if ch.isspace():
            i += 1
            continue
        tokens.append(ch)
        i += 1
    if buf:
        tokens.append("".join(buf))
    return tokens


def _is_ident(tok: str) -> bool:
    if not tok:
        return False
    if not (tok[0].isalpha() or tok[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in tok)


def _classify(ident: str, *, known_tables: frozenset[str]) -> str:
    if ident in known_tables:
        return "table"
    if ident.endswith("_CL") and ident not in known_tables:
        return "parser"
    if ident.startswith(_PARSER_PREFIXES):
        return "parser"
    return "unknown"


def _scan_statement(
    statement: str,
    *,
    known_tables: frozenset[str],
    let_bindings: dict[str, str],
) -> tuple[set[str], set[str], bool, dict[str, str]]:
    tokens = _tokenize(statement)
    tables: set[str] = set()
    parsers: set[str] = set()
    indeterminate = False
    bindings = dict(let_bindings)
    expect_table = True
    i = 0

    def consume_ident_as_table(ident: str) -> None:
        nonlocal indeterminate
        resolved = bindings.get(ident, ident)
        kind = _classify(resolved, known_tables=known_tables)
        if kind == "table":
            tables.add(resolved)
        elif kind == "parser":
            parsers.add(resolved)
        else:
            indeterminate = True

    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()

        if low == "let" and i + 3 < len(tokens) and tokens[i + 2] == "=":
            name = tokens[i + 1]
            rhs = tokens[i + 3]
            if _is_ident(name) and _is_ident(rhs):
                kind = _classify(rhs, known_tables=known_tables)
                if kind == "table":
                    bindings[name] = rhs
                    tables.add(rhs)
                elif kind == "parser":
                    bindings[name] = rhs
                    parsers.add(rhs)
                else:
                    indeterminate = True
            elif _is_ident(name) and not _is_ident(rhs):
                pass
            i += 4
            expect_table = True
            continue

        if low == "union":
            i += 1
            if i < len(tokens) and tokens[i] == "*":
                indeterminate = True
                i += 1
                expect_table = False
                continue
            while i < len(tokens):
                item = tokens[i]
                if item == "|":
                    break
                if item == ",":
                    i += 1
                    continue
                if item == "*":
                    indeterminate = True
                    i += 1
                    continue
                if _is_ident(item):
                    consume_ident_as_table(item)
                    i += 1
                    continue
                break
            expect_table = False
            continue

        if low == "join":
            i += 1
            if i < len(tokens) and tokens[i].lower() == "kind":
                i += 1
                if i < len(tokens) and tokens[i] == "=":
                    i += 1
                if i < len(tokens) and tokens[i].lower() in _JOIN_KINDS:
                    i += 1
            if i < len(tokens) and tokens[i] == "(":
                i += 1
                if i < len(tokens) and _is_ident(tokens[i]):
                    consume_ident_as_table(tokens[i])
                    i += 1
            expect_table = False
            continue

        if low == "search":
            i += 1
            if i < len(tokens) and tokens[i].lower() == "in":
                i += 1
            if i < len(tokens) and tokens[i] == "(":
                i += 1
                while i < len(tokens) and tokens[i] != ")":
                    item = tokens[i]
                    if item == ",":
                        i += 1
                        continue
                    if _is_ident(item):
                        consume_ident_as_table(item)
                    i += 1
            expect_table = False
            continue

        if low == "table" and i + 1 < len(tokens) and tokens[i + 1] == "(":
            indeterminate = True
            i += 2
            expect_table = False
            continue

        if expect_table and _is_ident(tok):
            if low in _NO_TABLE_COMMANDS:
                expect_table = False
                i += 1
                continue
            consume_ident_as_table(tok)
            expect_table = False
            i += 1
            continue

        if tok == "|":
            expect_table = False
        i += 1

    return tables, parsers, indeterminate, bindings


_SELF_TEST_KNOWN = frozenset(
    {
        "SigninLogs",
        "AuditLogs",
        "DeviceProcessEvents",
        "EmailEvents",
        "SecurityAlert",
        "OfficeActivity",
    }
)


def _self_test() -> int:
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "kql"
    if not root.is_dir():
        print(f"FAIL: fixture dir missing: {root}")
        return 1
    files = sorted(root.glob("*.kql"))
    if len(files) != 15:
        print(f"FAIL: expected 15 fixtures, got {len(files)}")
        return 1
    failed = 0
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
        refs = extract_table_refs(body, known_tables=_SELF_TEST_KNOWN)
        ok = (
            refs.tables == frozenset(expected_tables)
            and refs.parsers == frozenset(expected_parsers)
            and refs.indeterminate is expected_indet
        )
        status = "PASS" if ok else "FAIL"
        print(
            f"{status} {path.name} tables={sorted(refs.tables)} "
            f"parsers={sorted(refs.parsers)} indet={refs.indeterminate}"
        )
        if not ok:
            failed += 1
            print(
                f"  expected tables={sorted(expected_tables)} "
                f"parsers={sorted(expected_parsers)} indet={expected_indet}"
            )
    return 1 if failed else 0


if __name__ == "__main__":
    import sys

    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    print("usage: python -m licenselens.kql.table_refs --self-test")
    raise SystemExit(2)
