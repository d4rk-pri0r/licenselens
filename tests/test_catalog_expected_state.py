"""Lint contract for the copy-only ``expected_state`` check-catalog field.

Every registered check must carry a non-empty, ≤160-char, sentence-case
``expected_state`` that is byte-distinct from its ``customer_summary`` and
``description``. The report-facing mapping helper must be deterministic and
cover exactly the registered check set.
"""

from __future__ import annotations

import re

from licenselens.catalog.expected_states import expected_state_map
from licenselens.engine.loader import load_checks

MAX_EXPECTED_STATE_CHARS = 160


def test_every_registered_check_has_nonempty_expected_state():
    checks = load_checks()
    assert checks, "no checks registered"
    missing = [c.id for c in checks if not c.expected_state]
    assert not missing, f"checks with empty expected_state: {missing}"


def test_expected_state_length_within_cap():
    too_long = [
        (c.id, len(c.expected_state))
        for c in load_checks()
        if len(c.expected_state) > MAX_EXPECTED_STATE_CHARS
    ]
    assert not too_long, f"expected_state over {MAX_EXPECTED_STATE_CHARS} chars: {too_long}"


def test_expected_state_byte_distinct_from_customer_copy():
    dupes = [
        c.id
        for c in load_checks()
        if c.expected_state and c.expected_state in (c.customer_summary, c.description)
    ]
    assert not dupes, f"expected_state byte-equal to customer_summary/description: {dupes}"


def test_expected_state_is_one_sentence_case_sentence():
    malformed = [
        (c.id, c.expected_state)
        for c in load_checks()
        if not re.fullmatch(r"[A-Z][^.!?\n]*\.", c.expected_state)
    ]
    assert not malformed, f"expected_state not a single sentence-case sentence: {malformed}"


def test_mapping_is_deterministic():
    assert expected_state_map() == expected_state_map()


def test_mapping_covers_exactly_registered_checks():
    checks = load_checks()
    mapping = expected_state_map()
    registered_ids = {c.id for c in checks}
    assert set(mapping) == registered_ids, (
        f"mapping mismatch: missing={registered_ids - set(mapping)} "
        f"extra={set(mapping) - registered_ids}"
    )
    assert len(mapping) == len(registered_ids)
    assert all(mapping[cid] == next(c for c in checks if c.id == cid).expected_state
               for cid in mapping)
    assert not [cid for cid, text in mapping.items() if not text]


def test_loading_still_works_with_the_new_field():
    # Scan-time behavior is unchanged: the field is copy-only on the catalog
    # check definition and must not surface on findings.
    from licenselens.models import CheckDefinition, Finding

    checks = load_checks()
    for check in checks:
        assert isinstance(check, CheckDefinition)
    assert "expected_state" not in Finding.model_fields
