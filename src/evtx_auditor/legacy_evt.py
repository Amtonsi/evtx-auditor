from __future__ import annotations

import mmap
import struct
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
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


@dataclass(frozen=True)
class RawEvtRecord:
    EventID: int
    EventType: int
    EventCategory: int
    RecordNumber: int
    SourceName: str
    ComputerName: str
    TimeGenerated: int
    TimeWritten: int
    StringInserts: tuple[str, ...]
    Data: bytes


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


def _read_utf16z(buffer: bytes | mmap.mmap, start: int, limit: int) -> tuple[str, int]:
    if start < 0 or start >= limit:
        return "", start
    cursor = start
    while cursor + 1 < limit:
        if buffer[cursor] == 0 and buffer[cursor + 1] == 0:
            raw = bytes(buffer[start:cursor])
            return raw.decode("utf-16le", errors="replace"), cursor + 2
        cursor += 2
    return "", start


def _parse_raw_evt_record(record: bytes) -> RawEvtRecord:
    if len(record) < 60:
        raise ValueError("EVT record is too small")
    (
        record_length,
        signature,
        record_number,
        time_generated,
        time_written,
        event_id,
        event_type,
        number_of_strings,
        event_category,
        _reserved_flags,
        _closing_record_number,
        string_offset,
        _user_sid_length,
        _user_sid_offset,
        data_length,
        data_offset,
    ) = struct.unpack_from("<IIIIIIHHHHIIIIII", record, 0)
    if record_length != len(record):
        raise ValueError("EVT record length mismatch")
    if signature != 0x654C664C:
        raise ValueError("EVT record signature mismatch")

    data_limit = max(56, record_length - 4)
    source, cursor = _read_utf16z(record, 56, data_limit)
    computer, _cursor = _read_utf16z(record, cursor, data_limit)

    strings: list[str] = []
    cursor = string_offset
    for _index in range(number_of_strings):
        if cursor <= 0 or cursor >= data_limit:
            break
        value, next_cursor = _read_utf16z(record, cursor, data_limit)
        if next_cursor == cursor:
            break
        strings.append(value)
        cursor = next_cursor

    event_data = b""
    if (
        data_length > 0
        and data_offset > 0
        and data_offset + data_length <= data_limit
    ):
        event_data = bytes(record[data_offset : data_offset + data_length])

    return RawEvtRecord(
        EventID=event_id,
        EventType=event_type,
        EventCategory=event_category,
        RecordNumber=record_number,
        SourceName=source,
        ComputerName=computer,
        TimeGenerated=time_generated,
        TimeWritten=time_written,
        StringInserts=tuple(strings),
        Data=event_data,
    )


def _read_raw_evt_records(path: Path) -> Iterator[RawEvtRecord]:
    if path.stat().st_size == 0:
        return
    with path.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
            position = 0
            size = len(view)
            while True:
                signature_position = view.find(b"LfLe", position)
                if signature_position < 0:
                    break
                start = signature_position - 4
                if start >= 0 and start + 60 <= size:
                    record_length = struct.unpack_from("<I", view, start)[0]
                    end = start + record_length
                    if (
                        record_length >= 60
                        and end <= size
                        and struct.unpack_from("<I", view, end - 4)[0]
                        == record_length
                    ):
                        try:
                            yield _parse_raw_evt_record(bytes(view[start:end]))
                            position = end
                            continue
                        except ValueError:
                            pass
                position = signature_position + 4


def scan_evt(
    path: Path,
    context: EventContext,
    candidate_predicate: Callable[[int, int | None], bool],
    on_issue: Callable[[ParseIssue], None] | None = None,
    *,
    always_render_predicate: Callable[[int, int | None], bool] | None = None,
) -> Iterator[ScannedRecord]:
    del always_render_predicate
    try:
        yield from scan_evt_records(
            _read_backup_records(path),
            context,
            candidate_predicate,
            on_issue,
        )
    except Exception as api_error:
        records_found = False
        try:
            for scanned in scan_evt_records(
                _read_raw_evt_records(path),
                context,
                candidate_predicate,
                on_issue,
            ):
                records_found = True
                yield scanned
        except Exception as fallback_error:
            if on_issue is not None:
                on_issue(
                    ParseIssue(
                        0,
                        "Windows API не открыл EVT; прямое чтение тоже "
                        f"завершилось ошибкой: {fallback_error}; "
                        f"ошибка Windows API: {api_error}",
                    )
                )
            raise
        if not records_found and on_issue is not None:
            on_issue(
                ParseIssue(
                    0,
                    "Windows API не открыл EVT; прямое чтение не нашло "
                    f"записей: {api_error}",
                )
            )
