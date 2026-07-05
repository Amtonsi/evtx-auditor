from evtx_auditor.models import FindingCategory
from evtx_auditor.rules import classify_event


def test_native_level_one_is_critical(make_event):
    seeds = classify_event(
        make_event(
            event_id=41,
            level=1,
            channel="System",
            provider="Microsoft-Windows-Kernel-Power",
        )
    )

    assert seeds[0].category is FindingCategory.CRITICAL


def test_audit_log_clear_is_critical_even_without_level(make_event):
    seeds = classify_event(
        make_event(
            event_id=1102,
            level=None,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
        )
    )

    assert seeds[0].category is FindingCategory.CRITICAL
    assert "очищен" in seeds[0].title.lower()


def test_security_account_change_uses_specific_rule(make_event):
    event = make_event(
        event_id=4720,
        level=0,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        data={"TargetUserName": "new-user"},
    )

    seeds = classify_event(event)

    assert seeds[0].category is FindingCategory.SECURITY
    assert "new-user" in seeds[0].grouping_key


def test_4625_is_deferred_to_correlation(make_event):
    event = make_event(event_id=4625, level=0, channel="Security")

    assert classify_event(event) == []


def test_unknown_level_two_uses_rendered_message(make_event):
    event = make_event(
        event_id=1000,
        level=2,
        channel="Application",
        rendered_message="Application crashed with code 5",
    )

    seed = classify_event(event)[0]

    assert seed.category is FindingCategory.ERROR
    assert "Application crashed" in seed.explanation


def test_xp_security_log_clear_517_is_critical(make_event):
    seeds = classify_event(
        make_event(
            event_id=517,
            level=0,
            channel="Security",
            provider="Security",
            source_format="EVT",
        )
    )

    assert seeds[0].category is FindingCategory.CRITICAL
    assert "XP" in seeds[0].title


def test_xp_failed_logon_529_is_security_finding(make_event):
    seeds = classify_event(
        make_event(
            event_id=529,
            level=0,
            channel="Security",
            provider="Security",
            data={"String_1": "operator", "String_3": "192.168.1.10"},
            source_format="EVT",
        )
    )

    assert seeds[0].category is FindingCategory.SECURITY
    assert "operator" in seeds[0].grouping_key
