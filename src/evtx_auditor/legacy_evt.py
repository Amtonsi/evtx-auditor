from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import EventRecord
from .parser import EventContext, FastEventMetadata, ParseIssue, ScannedRecord


EVENT_TYPE_LABELS = {
    1: "Error",
    2: "Warning",
    4: "Information",
    8: "Audit Success",
    16: "Audit Failure",
}

EVENT_TYPE_LEVELS = {
    1: 2,
    2: 3,
    4: 4,
    8: 0,
    16: 0,
}


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _classic_event_id(value: Any) -> int:
    raw = _int_or_none(value)
    if raw is None:
        return 0
    return raw & 0xFFFF


def _timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_data_hex(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    try:
        return bytes(value).hex()
    except (TypeError, ValueError):
        return str(value)


def normalize_evt_record(
    record: Any,
    context: EventContext,
    record_index: int,
) -> EventRecord:
    event_type = _int_or_none(getattr(record, "EventType", None))
    event_id = _classic_event_id(getattr(record, "EventID", None))
    raw_event_id = _int_or_none(getattr(record, "EventID", None))
    strings = list(getattr(record, "StringInserts", None) or [])
    data = {
        "EventType": EVENT_TYPE_LABELS.get(event_type or 0, str(event_type or "")),
        "EventCategory": str(getattr(record, "EventCategory", "") or ""),
    }
    if raw_event_id is not None and raw_event_id != event_id:
        data["RawEventID"] = str(raw_event_id)
    for index, value in enumerate(strings, start=1):
        data[f"String_{index}"] = str(value)
    event_data_hex = _event_data_hex(getattr(record, "Data", None))
    if event_data_hex:
        data["EventDataHex"] = event_data_hex

    timestamp = _timestamp(getattr(record, "TimeGenerated", None))
    warnings: list[str] = []
    if timestamp is None:
        warnings.append("missing_timestamp")

    channel = Path(context.log_file).stem
    provider = str(getattr(record, "SourceName", "") or channel)
    rendered_message = "\n".join(str(value) for value in strings) or None
    return EventRecord(
        node=context.node,
        archive=context.archive,
        log_file=context.log_file,
        channel=channel,
        provider=provider,
        event_id=event_id,
        level=EVENT_TYPE_LEVELS.get(event_type or 0),
        timestamp=timestamp,
        record_id=_int_or_none(getattr(record, "RecordNumber", None)) or record_index,
        computer=str(getattr(record, "ComputerName", "") or ""),
        task=_int_or_none(getattr(record, "EventCategory", None)),
        opcode=None,
        keywords=EVENT_TYPE_LABELS.get(event_type or 0, ""),
        data=data,
        rendered_message=rendered_message,
        parse_warnings=tuple(warnings),
        source_format="EVT",
    )


def scan_evt_records(
    records: Iterable[Any],
    context: EventContext,
    candidate_predicate: Callable[[int, int | None], bool],
    on_issue: Callable[[ParseIssue], None] | None = None,
) -> Iterator[ScannedRecord]:
    issue_handler = on_issue or (lambda issue: None)
    for index, record in enumerate(records, start=1):
        try:
            event = normalize_evt_record(record, context, index)
        except Exception as error:
            issue_handler(ParseIssue(index, str(error)))
            yield ScannedRecord(FastEventMetadata(0, None, None), None)
            continue
        metadata = FastEventMetadata(
            event.event_id,
            event.level,
            event.timestamp,
            event.record_id,
            event.provider,
            event.channel,
        )
        yield ScannedRecord(
            metadata,
            event if candidate_predicate(event.event_id, event.level) else None,
        )


def _read_backup_records(path: Path) -> Iterator[Any]:
    try:
        import win32evtlog
    except ImportError as error:
        raise RuntimeError(
            "Для чтения Windows XP EVT требуется pywin32."
        ) from error

    handle = win32evtlog.OpenBackupEventLog(None, str(path))
    try:
        flags = (
            win32evtlog.EVENTLOG_FORWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            yield from records
    finally:
        win32evtlog.CloseEventLog(handle)


def scan_evt(
    path: Path,
    context: EventContext,
    candidate_predicate: Callable[[int, int | None], bool],
    on_issue: Callable[[ParseIssue], None] | None = None,
    *,
    always_render_predicate: Callable[[int, int | None], bool] | None = None,
) -> Iterator[ScannedRecord]:
    del always_render_predicate
    yield from scan_evt_records(
        _read_backup_records(path),
        context,
        candidate_predicate,
        on_issue,
    )
