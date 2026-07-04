from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evtx_auditor.models import (
    AuditRun,
    Diagnostic,
    EventRecord,
    Finding,
    FindingCategory,
    NodeResult,
)


@pytest.fixture
def make_event():
    def factory(**values):
        defaults = {
            "node": "HOST",
            "archive": "events.zip",
            "log_file": "System.evtx",
            "channel": "System",
            "provider": "Demo-Provider",
            "event_id": 1,
            "level": 4,
            "timestamp": datetime(2026, 7, 2, 9, 0, tzinfo=timezone.utc),
            "record_id": 1,
            "computer": "HOST",
            "task": None,
            "opcode": None,
            "keywords": "",
            "data": {},
            "rendered_message": None,
            "parse_warnings": (),
        }
        defaults.update(values)
        return EventRecord(**defaults)

    return factory


def _sample_run(rendered_message: str) -> AuditRun:
    created = datetime(2026, 7, 4, 14, 30, tzinfo=timezone.utc)
    event = EventRecord(
        node="40010-SRV-04B",
        archive="2026-07-02_EventLogs_40010-SRV-04B.zip",
        log_file="System.evtx",
        channel="System",
        provider="Microsoft-Windows-Kernel-Power",
        event_id=41,
        level=1,
        timestamp=created - timedelta(days=1),
        record_id=184031,
        computer="40010-SRV-04B",
        task=63,
        opcode=0,
        keywords="0x8000400000000002",
        data={"BugcheckCode": "0"},
        rendered_message=rendered_message,
    )
    finding = Finding.from_events(
        category=FindingCategory.CRITICAL,
        priority=100,
        title="Перезагрузка без корректного завершения работы",
        explanation=rendered_message,
        recommendation="Проверить питание, ИБП и дампы памяти.",
        grouping_key=("40010-SRV-04B", "System", "Kernel-Power", "41"),
        events=[event],
    )
    first = NodeResult.complete(
        "40010-SRV-04B",
        [finding],
        [Diagnostic.info("System.evtx", "Прочитано успешно")],
        period_start=created - timedelta(days=30),
        period_end=created,
        records_read=1000,
        logs_seen=("Application.evtx", "Security.evtx", "System.evtx"),
        archives_seen=("2026-07-02_EventLogs_40010-SRV-04B.zip",),
    )
    second = NodeResult.complete(
        "NEW-OPER-4",
        [],
        [Diagnostic.info("Security.evtx", "Прочитано успешно")],
        period_start=created - timedelta(days=30),
        period_end=created,
        records_read=800,
        logs_seen=("Application.evtx", "Security.evtx", "System.evtx"),
        archives_seen=("2026-07-02_EventLogs_NEW-OPER-4.zip",),
    )
    return AuditRun(
        source_root=Path(r"C:\Users\impal\Downloads\АУДИТ 2"),
        created_at=created,
        nodes=(first, second),
        metadata={"archive_count": 2, "evtx_count": 6},
    )


@pytest.fixture
def sample_audit_run():
    return _sample_run("Компьютер был перезагружен без корректного завершения.")


@pytest.fixture
def sample_audit_run_with_script_text():
    return _sample_run("</script><script>alert(1)</script>")
