from datetime import datetime, timezone

import pytest

from evtx_auditor.models import EventRecord


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

