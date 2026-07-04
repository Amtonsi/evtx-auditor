from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from Evtx.Evtx import Evtx

from .models import EventRecord


@dataclass(frozen=True)
class EventContext:
    node: str
    archive: str
    log_file: str


class ParseIssue(RuntimeError):
    def __init__(self, record_index: int, message: str) -> None:
        self.record_index = record_index
        self.message = message
        super().__init__(f"Запись {record_index}: {message}")


@dataclass(frozen=True)
class FastEventMetadata:
    event_id: int
    level: int | None
    timestamp: datetime | None


@dataclass(frozen=True)
class ScannedRecord:
    metadata: FastEventMetadata
    event: EventRecord | None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element: ElementTree.Element | None, name: str):
    if element is None:
        return None
    return next(
        (item for item in list(element) if _local_name(item.tag) == name),
        None,
    )


def _text(element: ElementTree.Element | None, name: str) -> str:
    item = _child(element, name)
    return (item.text or "").strip() if item is not None else ""


def _int_or_none(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return int(value, 0)
        except ValueError:
            return None


def _timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _flatten_userdata(
    element: ElementTree.Element,
    prefix: tuple[str, ...] = ("UserData",),
) -> dict[str, str]:
    values: dict[str, str] = {}
    children = list(element)
    if not children:
        value = (element.text or "").strip()
        if value:
            values[".".join(prefix)] = value
        return values
    for child in children:
        values.update(
            _flatten_userdata(child, (*prefix, _local_name(child.tag)))
        )
    return values


def parse_event_xml(xml_text: str, context: EventContext) -> EventRecord:
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as error:
        raise ValueError(f"Некорректный XML события: {error}") from error

    system = _child(root, "System")
    provider_element = _child(system, "Provider")
    provider = (
        provider_element.attrib.get("Name", "").strip()
        if provider_element is not None
        else ""
    )
    event_id = _int_or_none(_text(system, "EventID"))
    time_element = _child(system, "TimeCreated")
    timestamp = _timestamp(
        time_element.attrib.get("SystemTime", "")
        if time_element is not None
        else ""
    )
    record_id = _int_or_none(_text(system, "EventRecordID"))
    channel = _text(system, "Channel")

    data: dict[str, str] = {}
    event_data = _child(root, "EventData")
    unnamed_index = 0
    if event_data is not None:
        for item in list(event_data):
            if _local_name(item.tag) != "Data":
                continue
            name = item.attrib.get("Name", "").strip()
            if not name:
                unnamed_index += 1
                name = f"Data_{unnamed_index}"
            data[name] = "".join(item.itertext()).strip()

    user_data = _child(root, "UserData")
    if user_data is not None:
        data.update(_flatten_userdata(user_data))

    rendering_info = _child(root, "RenderingInfo")
    rendered_message = _text(rendering_info, "Message") or None

    warnings: list[str] = []
    if timestamp is None:
        warnings.append("missing_timestamp")
    if record_id is None:
        warnings.append("missing_record_id")
    if not channel:
        warnings.append("missing_channel")
    if not provider:
        warnings.append("missing_provider")

    return EventRecord(
        node=context.node,
        archive=context.archive,
        log_file=context.log_file,
        channel=channel or Path(context.log_file).stem,
        provider=provider,
        event_id=event_id or 0,
        level=_int_or_none(_text(system, "Level")),
        timestamp=timestamp,
        record_id=record_id,
        computer=_text(system, "Computer"),
        task=_int_or_none(_text(system, "Task")),
        opcode=_int_or_none(_text(system, "Opcode")),
        keywords=_text(system, "Keywords"),
        data=data,
        rendered_message=rendered_message,
        parse_warnings=tuple(warnings),
    )


def fast_record_metadata(record) -> FastEventMetadata:
    substitutions = record.root().substitutions()
    if len(substitutions) < 7:
        raise ValueError("Недостаточно системных подстановок EVTX")
    event_id = _int_or_none(substitutions[3].string())
    level = _int_or_none(substitutions[0].string())
    timestamp = _timestamp(substitutions[6].string())
    if event_id is None:
        raise ValueError("Event ID не прочитан из EVTX")
    if level is not None and not 0 <= level <= 255:
        raise ValueError(f"Некорректный Level: {level}")
    return FastEventMetadata(event_id, level, timestamp)


def scan_records(
    records: Iterable,
    context: EventContext,
    candidate_predicate: Callable[[int, int | None], bool],
    on_issue: Callable[[ParseIssue], None] | None = None,
) -> Iterator[ScannedRecord]:
    issue_handler = on_issue or (lambda issue: None)
    for index, record in enumerate(records, start=1):
        try:
            metadata = fast_record_metadata(record)
        except Exception:
            try:
                event = parse_event_xml(record.xml(), context)
            except Exception as error:
                issue_handler(ParseIssue(index, str(error)))
                try:
                    fallback_time = record.timestamp()
                except Exception:
                    fallback_time = None
                yield ScannedRecord(
                    FastEventMetadata(0, None, fallback_time), None
                )
                continue
            metadata = FastEventMetadata(
                event.event_id, event.level, event.timestamp
            )
            yield ScannedRecord(
                metadata,
                event
                if candidate_predicate(event.event_id, event.level)
                else None,
            )
            continue

        if not candidate_predicate(metadata.event_id, metadata.level):
            yield ScannedRecord(metadata, None)
            continue
        try:
            event = parse_event_xml(record.xml(), context)
        except Exception as error:
            issue_handler(ParseIssue(index, str(error)))
            yield ScannedRecord(metadata, None)
            continue
        yield ScannedRecord(metadata, event)


def scan_evtx(
    path: Path,
    context: EventContext,
    candidate_predicate: Callable[[int, int | None], bool],
    on_issue: Callable[[ParseIssue], None] | None = None,
) -> Iterator[ScannedRecord]:
    with Evtx(str(path)) as event_log:
        yield from scan_records(
            event_log.records(), context, candidate_predicate, on_issue
        )


def iter_evtx(
    path: Path,
    context: EventContext,
    on_issue: Callable[[ParseIssue], None] | None = None,
) -> Iterator[EventRecord]:
    issue_handler = on_issue or (lambda issue: None)
    with Evtx(str(path)) as event_log:
        for index, record in enumerate(event_log.records(), start=1):
            try:
                yield parse_event_xml(record.xml(), context)
            except Exception as error:
                issue_handler(ParseIssue(index, str(error)))
