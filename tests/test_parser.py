from pathlib import Path

from evtx_auditor.parser import EventContext, parse_event_xml

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
