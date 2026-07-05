from datetime import datetime, timezone

from evtx_auditor.legacy_evt import (
    normalize_evt_record,
    scan_evt_records,
)
from evtx_auditor.parser import EventContext


class FakeEvtRecord:
    EventID = 529
    EventType = 16
    EventCategory = 2
    RecordNumber = 42
    SourceName = "Security"
    ComputerName = "XP-HOST"
    TimeGenerated = datetime(2026, 7, 1, 10, 15, tzinfo=timezone.utc)
    TimeWritten = datetime(2026, 7, 1, 10, 16, tzinfo=timezone.utc)
    StringInserts = ["operator", "WORKGROUP", "192.168.1.10"]
    Data = b"\x01\x02"


def test_normalizes_legacy_evt_record_to_event_record():
    event = normalize_evt_record(
        FakeEvtRecord(),
        EventContext("XP-HOST", "xp.zip", "Security.evt"),
        1,
    )

    assert event.source_format == "EVT"
    assert event.node == "XP-HOST"
    assert event.channel == "Security"
    assert event.provider == "Security"
    assert event.event_id == 529
    assert event.level == 0
    assert event.timestamp == FakeEvtRecord.TimeGenerated
    assert event.record_id == 42
    assert event.computer == "XP-HOST"
    assert event.task == 2
    assert event.keywords == "Audit Failure"
    assert event.data["String_1"] == "operator"
    assert event.data["EventDataHex"] == "0102"


def test_scan_evt_records_keeps_metadata_for_non_candidates():
    scanned = list(
        scan_evt_records(
            [FakeEvtRecord()],
            EventContext("XP-HOST", "xp.zip", "Security.evt"),
            lambda event_id, level: False,
        )
    )

    assert len(scanned) == 1
    assert scanned[0].metadata.event_id == 529
    assert scanned[0].metadata.level == 0
    assert scanned[0].event is None
