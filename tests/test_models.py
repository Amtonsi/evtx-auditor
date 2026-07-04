def test_package_exposes_version():
    import evtx_auditor

    assert evtx_auditor.__version__ == "1.0.0"


def test_node_with_findings_is_checked():
    from datetime import datetime, timezone

    from evtx_auditor.models import (
        Diagnostic,
        EventRecord,
        Finding,
        FindingCategory,
        NodeResult,
        NodeStatus,
    )

    event = EventRecord(
        node="HOST-1",
        archive="host.zip",
        log_file="System.evtx",
        channel="System",
        provider="Microsoft-Windows-Kernel-Power",
        event_id=41,
        level=1,
        timestamp=datetime(2026, 7, 2, tzinfo=timezone.utc),
        record_id=100,
        computer="HOST-1",
        task=None,
        opcode=None,
        keywords="",
        data={},
        rendered_message=None,
    )
    finding = Finding.from_events(
        category=FindingCategory.CRITICAL,
        priority=100,
        title="Аварийная перезагрузка",
        explanation="Система завершила работу некорректно.",
        recommendation="Проверить питание и дампы.",
        grouping_key=("HOST-1", "System", "Kernel-Power", "41"),
        events=[event],
    )
    result = NodeResult.complete(
        "HOST-1", [finding], [Diagnostic.info("System.evtx", "ok")]
    )

    assert result.status is NodeStatus.CHECKED
    assert result.critical_count == 1
    assert finding.first_seen == event.timestamp
    assert finding.last_seen == event.timestamp
