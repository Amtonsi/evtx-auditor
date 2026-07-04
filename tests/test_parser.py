from pathlib import Path

from evtx_auditor.parser import (
    EventContext,
    fast_record_metadata,
    parse_event_xml,
    scan_records,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_system_and_event_data():
    event = parse_event_xml(
        (FIXTURES / "security_4625.xml").read_text(encoding="utf-8"),
        EventContext("NEW-OPER-4", "events.zip", "Security.evtx"),
    )

    assert event.node == "NEW-OPER-4"
    assert event.channel == "Security"
    assert event.event_id == 4625
    assert event.data["TargetUserName"] == "operator"
    assert event.data["IpAddress"] == "192.168.10.24"
    assert event.timestamp is not None


def test_missing_optional_fields_become_warnings():
    event = parse_event_xml(
        (FIXTURES / "partial_event.xml").read_text(encoding="utf-8"),
        EventContext("HOST", "events.zip", "System.evtx"),
    )

    assert event.timestamp is None
    assert event.record_id is None
    assert "missing_timestamp" in event.parse_warnings
    assert event.data["UserData.Example.Path"].endswith("app.exe")


def test_parses_rendered_message_and_unnamed_data():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Demo"/><EventID>5</EventID><Level>2</Level>
      <TimeCreated SystemTime="2026-07-02T09:10:11Z"/><EventRecordID>7</EventRecordID>
      <Channel>Application</Channel><Computer>HOST</Computer></System>
      <EventData><Data>first</Data><Data>second</Data></EventData>
      <RenderingInfo><Message>Rendered description</Message></RenderingInfo>
    </Event>"""

    event = parse_event_xml(
        xml, EventContext("HOST", "events.zip", "Application.evtx")
    )

    assert event.data["Data_1"] == "first"
    assert event.data["Data_2"] == "second"
    assert event.rendered_message == "Rendered description"


class _FakeValue:
    def __init__(self, value):
        self.value = value

    def string(self):
        return self.value


class _FakeRoot:
    def __init__(self, event_id, level, timestamp):
        self.values = [_FakeValue("") for _ in range(17)]
        self.values[0] = _FakeValue(str(level))
        self.values[3] = _FakeValue(str(event_id))
        self.values[6] = _FakeValue(timestamp)

    def substitutions(self):
        return self.values


class _FakeRecord:
    def __init__(self, event_id, level, timestamp, xml):
        self.root_value = _FakeRoot(event_id, level, timestamp)
        self.xml_value = xml
        self.xml_calls = 0

    def root(self):
        return self.root_value

    def xml(self):
        self.xml_calls += 1
        return self.xml_value


def test_fast_metadata_reads_system_fields_without_rendering_xml():
    record = _FakeRecord(
        41, 1, "2026-07-02 01:02:03+00:00", "<unused/>"
    )

    metadata = fast_record_metadata(record)

    assert metadata.event_id == 41
    assert metadata.level == 1
    assert metadata.timestamp is not None
    assert record.xml_calls == 0


def test_scan_records_renders_xml_only_for_candidates():
    critical_xml = (FIXTURES / "critical_event.xml").read_text(
        encoding="utf-8"
    )
    candidate = _FakeRecord(
        41, 1, "2026-07-02 01:02:03+00:00", critical_xml
    )
    ordinary = _FakeRecord(
        1, 4, "2026-07-02 01:02:04+00:00", "<invalid/>"
    )

    scanned = list(
        scan_records(
            [candidate, ordinary],
            EventContext("HOST", "events.zip", "System.evtx"),
            lambda event_id, level: level in {1, 2},
        )
    )

    assert len(scanned) == 2
    assert scanned[0].event is not None
    assert scanned[1].event is None
    assert candidate.xml_calls == 1
    assert ordinary.xml_calls == 0
