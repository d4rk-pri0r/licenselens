from licenselens.engine.loader import load_checks


def test_loads_ten_v01_checks():
    checks = load_checks()
    ids = {c.id for c in checks}
    expected = {
        "id-pim-unused",
        "id-ca-priv-gaps",
        "id-idprotect-off",
        "id-dormant-privileged",
        "mdo-p2-policies-default",
        "mde-onboard-gap",
        "mdi-sensors-missing",
        "sen-analytics-rule-coverage",
        "sen-ueba-not-enabled",
        "pur-dlp-not-enforced",
    }
    assert expected.issubset(ids)
    assert len(checks) >= 10
    for check in checks:
        assert check.customer_title, check.id
        assert check.customer_summary, check.id
        assert check.customer_next_step, check.id


def test_all_enabled_checks_have_pack_metadata():
    checks = load_checks()
    for check in checks:
        if not check.enabled:
            continue
        assert check.impact.value in {"high", "medium", "low"}, check.id
        assert check.effort.value in {"minutes", "hours", "half_day", "days"}, check.id
        assert check.blast_radius.value in {"admin", "all_users", "devices", "data"}, check.id
        assert check.pack.value in {"identity", "email", "endpoint", "starter"}, check.id
        assert check.exposure_class.value in {"none", "elevated", "exposed"}, check.id


def test_pack_coverage():
    checks = load_checks()
    packs = {c.pack.value for c in checks if c.enabled}
    # Core packs must each contain at least one enabled check.
    for required in ("identity", "email", "endpoint"):
        assert required in packs, f"pack {required!r} has no checks"
    assert "starter" in packs
