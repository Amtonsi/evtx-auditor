from datetime import datetime, timedelta, timezone

from evtx_auditor.analyzer import analyze_events
from evtx_auditor.models import (
    Diagnostic,
    FindingCategory,
    NodeStatus,
)


def test_period_is_relative_to_latest_event(make_event):
    latest = datetime(2026, 7, 2, tzinfo=timezone.utc)
    events = [
        make_event(
            event_id=1000,
            level=2,
            timestamp=latest - timedelta(days=31),
            record_id=1,
        ),
        make_event(
            event_id=1001,
            level=2,
            timestamp=latest - timedelta(days=29),
            record_id=2,
        ),
        make_event(event_id=1, level=4, timestamp=latest, record_id=3),
    ]

    result = analyze_events(
        "HOST", events, diagnostics=[], logs_seen=("System.evtx",)
    )

    assert result.period_start == latest - timedelta(days=30)
    assert [item.events[0].event_id for item in result.findings] == [1001]


def test_custom_period_is_relative_to_latest_event(make_event):
    latest = datetime(2026, 7, 2, tzinfo=timezone.utc)
    events = [
        make_event(
            event_id=1000,
            level=2,
            timestamp=latest - timedelta(days=10),
            record_id=1,
        ),
        make_event(
            event_id=1001,
            level=2,
            timestamp=latest - timedelta(days=5),
            record_id=2,
        ),
        make_event(event_id=1, level=4, timestamp=latest, record_id=3),
    ]

    result = analyze_events(
        "HOST",
        events,
        diagnostics=[],
        logs_seen=("System.evtx",),
        analysis_days=7,
    )

    assert result.period_start == latest - timedelta(days=7)
    assert [item.events[0].event_id for item in result.findings] == [1001]


def test_ten_failed_logons_in_fifteen_minutes_create_one_security_finding(
    make_event,
):
    started = datetime(2026, 7, 2, 9, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            event_id=4625,
            level=0,
            channel="Security",
            timestamp=started + timedelta(minutes=index),
            record_id=index + 1,
            data={
                "TargetUserName": "operator",
                "IpAddress": "192.168.10.24",
                "LogonType": "3",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
            },
        )
        for index in range(10)
    ]

    result = analyze_events(
        "HOST", events, diagnostics=[], logs_seen=("Security.evtx",)
    )

    assert len(result.findings) == 1
    assert result.findings[0].category is FindingCategory.SECURITY
    assert len(result.findings[0].events) == 10


def test_nine_failed_logons_do_not_create_finding(make_event):
    started = datetime(2026, 7, 2, 9, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            event_id=4625,
            level=0,
            channel="Security",
            timestamp=started + timedelta(minutes=index),
            record_id=index + 1,
            data={"TargetUserName": "operator", "IpAddress": "10.0.0.1"},
        )
        for index in range(9)
    ]

    result = analyze_events(
        "HOST", events, diagnostics=[], logs_seen=("Security.evtx",)
    )

    assert result.status is NodeStatus.NO_FINDINGS


def test_repeated_errors_are_grouped_but_evidence_is_preserved(make_event):
    events = [
        make_event(
            event_id=1000,
            level=2,
            record_id=index,
            rendered_message="Service stopped unexpectedly",
        )
        for index in range(1, 4)
    ]

    result = analyze_events(
        "HOST", events, diagnostics=[], logs_seen=("System.evtx",)
    )

    assert len(result.findings) == 1
    assert len(result.findings[0].events) == 3


def test_processing_error_makes_node_partial(make_event):
    result = analyze_events(
        "HOST",
        [make_event(event_id=1, level=4)],
        diagnostics=[Diagnostic.error("Security.evtx", "Файл повреждён")],
        logs_seen=("System.evtx",),
    )

    assert result.status is NodeStatus.PARTIAL


def test_unremediated_defender_detection_is_critical(make_event):
    event = make_event(
        event_id=1116,
        level=4,
        provider="Microsoft-Windows-Windows Defender",
        data={"Threat ID": "214772", "Threat Name": "Test threat"},
    )

    result = analyze_events(
        "HOST", [event], diagnostics=[], logs_seen=("System.evtx",)
    )

    assert result.findings[0].category is FindingCategory.CRITICAL
