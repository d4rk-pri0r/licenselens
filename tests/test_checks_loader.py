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
