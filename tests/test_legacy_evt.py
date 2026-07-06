import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
import evtx_auditor.legacy_evt as legacy_evt
from evtx_auditor.legacy_evt import (
    normalize_evt_record,
    scan_evt,
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


def _utf16z(value: str) -> bytes:
    return value.encode("utf-16le") + b"\x00\x00"


def _raw_evt_record() -> bytes:
    source = _utf16z("Security")
    computer = _utf16z("XP-HOST")
    strings = _utf16z("operator") + _utf16z("WORKGROUP") + _utf16z("192.168.1.10")
    data = b"\x01\x02\x03\x04"
    string_offset = 56 + len(source) + len(computer)
    data_offset = string_offset + len(strings)
    record_length = data_offset + len(data) + 4
    record = bytearray(record_length)
    struct.pack_into(
        "<IIIIIIHHHHIIIIII",
        record,
        0,
        record_length,
        0x654C664C,
        42,
        1782900900,
        1782900960,
        529,
        16,
        3,
        2,
        0,
        0,
        string_offset,
        0,
        0,
        len(data),
        data_offset,
    )
    cursor = 56
    record[cursor : cursor + len(source)] = source
    cursor += len(source)
    record[cursor : cursor + len(computer)] = computer
    record[string_offset : string_offset + len(strings)] = strings
    record[data_offset : data_offset + len(data)] = data
    struct.pack_into("<I", record, record_length - 4, record_length)
    return bytes(record)


def test_scan_evt_falls_back_to_raw_records_when_windows_api_rejects_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    evt_path = tmp_path / "Security.evt"
    evt_path.write_bytes(b"bad header area" + _raw_evt_record())

    def broken_backup_reader(path: Path):
        raise OSError(1500, "OpenBackupEventLogW", "Журнал событий поврежден.")

    monkeypatch.setattr(legacy_evt, "_read_backup_records", broken_backup_reader)

    scanned = list(
        scan_evt(
            evt_path,
            EventContext("XP-HOST", "xp.zip", "Security.evt"),
            lambda event_id, level: event_id == 529,
        )
    )

    assert len(scanned) == 1
    assert scanned[0].metadata.event_id == 529
    assert scanned[0].event is not None
    assert scanned[0].event.source_format == "EVT"
    assert scanned[0].event.provider == "Security"
    assert scanned[0].event.computer == "XP-HOST"
    assert scanned[0].event.data["String_1"] == "operator"
