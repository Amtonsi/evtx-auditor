from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from .models import (
    Diagnostic,
    EventRecord,
    Finding,
    FindingCategory,
    FindingSeed,
    NodeResult,
)
from .rules import classify_event

ANALYSIS_DAYS = 30
FAILED_LOGON_THRESHOLD = 10
FAILED_LOGON_WINDOW = timedelta(minutes=15)


def _event_sort_key(event: EventRecord):
    return (
        event.timestamp or datetime.max.replace(tzinfo=timezone.utc),
        event.record_id or 0,
    )


def _security_value(event: EventRecord, key: str) -> str:
    value = event.data.get(key, "").strip()
    return value if value and value != "-" else "не указано"


def correlate_failed_logons(
    events: list[EventRecord],
) -> list[FindingSeed]:
    failed = [
        event
        for event in events
        if event.event_id == 4625 and event.timestamp is not None
    ]
    dimensions: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)
    for event in failed:
        user = event.data.get("TargetUserName", "").strip().casefold()
        address = event.data.get("IpAddress", "").strip().casefold()
        if user and user != "-":
            dimensions[("user", user)].append(event)
        if address and address != "-":
            dimensions[("address", address)].append(event)

    flagged: dict[int, EventRecord] = {}
    for dimension_events in dimensions.values():
        ordered = sorted(dimension_events, key=_event_sort_key)
        window: deque[EventRecord] = deque()
        for event in ordered:
            window.append(event)
            while (
                window
                and event.timestamp is not None
                and window[0].timestamp is not None
                and event.timestamp - window[0].timestamp > FAILED_LOGON_WINDOW
            ):
                window.popleft()
            if len(window) >= FAILED_LOGON_THRESHOLD:
                for matched in window:
                    flagged[id(matched)] = matched

    seeds: list[FindingSeed] = []
    for event in sorted(flagged.values(), key=_event_sort_key):
        user = _security_value(event, "TargetUserName")
        address = _security_value(event, "IpAddress")
        seeds.append(
            FindingSeed(
                category=FindingCategory.SECURITY,
                priority=88,
                title="Множественные неудачные попытки входа",
                explanation=(
                    "За 15 минут зарегистрировано не менее 10 ошибок входа "
                    "для общей учётной записи или адреса источника."
                ),
                recommendation=(
                    "Проверить принадлежность адреса, сохранённые пароли служб, "
                    "задания и возможный подбор учётных данных."
                ),
                grouping_key=(
                    event.node,
                    "Security",
                    event.provider,
                    "4625",
                    user,
                    address,
                    _security_value(event, "LogonType"),
                ),
                event=event,
            )
        )
    return seeds


def _threat_key(event: EventRecord) -> tuple[str, str, str]:
    return (
        event.data.get("Threat ID", event.data.get("ThreatID", "")).strip(),
        event.data.get("Threat Name", event.data.get("ThreatName", "")).strip(),
        event.data.get("Path", "").strip(),
    )


def _upgrade_unremediated_defender(
    seeds: list[FindingSeed], events: list[EventRecord]
) -> list[FindingSeed]:
    remediations = [
        event
        for event in events
        if event.event_id == 1117 and "defender" in event.provider.casefold()
    ]
    upgraded: list[FindingSeed] = []
    for seed in seeds:
        event = seed.event
        if event.event_id != 1116 or "defender" not in event.provider.casefold():
            upgraded.append(seed)
            continue
        key = _threat_key(event)
        remediated = any(
            _threat_key(item) == key
            and item.timestamp is not None
            and event.timestamp is not None
            and item.timestamp >= event.timestamp
            for item in remediations
        )
        if remediated:
            upgraded.append(seed)
            continue
        upgraded.append(
            FindingSeed(
                category=FindingCategory.CRITICAL,
                priority=97,
                title="Угроза Defender без подтверждения устранения",
                explanation=(
                    "Обнаружение Microsoft Defender не имеет последующего "
                    "события успешного действия в доступном периоде."
                ),
                recommendation=(
                    "Проверить состояние угрозы в Microsoft Defender, выполнить "
                    "полное сканирование и исследовать указанный путь."
                ),
                grouping_key=(
                    *seed.grouping_key,
                    "unremediated",
                ),
                event=event,
            )
        )
    return upgraded


def group_seeds(seeds: list[FindingSeed]) -> list[Finding]:
    grouped: dict[tuple[str, ...], list[FindingSeed]] = defaultdict(list)
    for seed in seeds:
        grouped[seed.grouping_key].append(seed)

    findings: list[Finding] = []
    for key, values in grouped.items():
        example = values[0]
        events = sorted((value.event for value in values), key=_event_sort_key)
        findings.append(
            Finding.from_events(
                category=example.category,
                priority=example.priority,
                title=example.title,
                explanation=example.explanation,
                recommendation=example.recommendation,
                grouping_key=key,
                events=events,
            )
        )
    return sorted(
        findings,
        key=lambda item: (
            -item.priority,
            -(item.last_seen or datetime.min.replace(tzinfo=timezone.utc)).timestamp(),
            item.title.casefold(),
        ),
    )


def analyze_events(
    node: str,
    events: Iterable[EventRecord],
    diagnostics: list[Diagnostic],
    logs_seen: tuple[str, ...],
    *,
    latest_timestamp: datetime | None = None,
    records_read: int | None = None,
    archives_seen: tuple[str, ...] = (),
    analysis_days: int = ANALYSIS_DAYS,
) -> NodeResult:
    records = list(events)
    valid_timestamps = [
        event.timestamp for event in records if event.timestamp is not None
    ]
    latest = latest_timestamp or (
        max(valid_timestamps) if valid_timestamps else None
    )
    current_diagnostics = list(diagnostics)
    missing_timestamps = sum(
        event.timestamp is None for event in records
    )
    if missing_timestamps:
        current_diagnostics.append(
            Diagnostic.warning(
                node,
                f"Пропущено событий без корректного времени: {missing_timestamps}",
            )
        )

    total_read = records_read if records_read is not None else len(records)
    if latest is None:
        current_diagnostics.append(
            Diagnostic.error(node, "Нет событий с корректной временной меткой")
        )
        if not records:
            return NodeResult.failed(
                node,
                current_diagnostics,
                records_read=total_read,
                logs_seen=logs_seen,
                archives_seen=archives_seen,
            )
        return NodeResult.complete(
            node,
            [],
            current_diagnostics,
            records_read=total_read,
            logs_seen=logs_seen,
            archives_seen=archives_seen,
        )

    cutoff = latest - timedelta(days=max(1, int(analysis_days)))
    in_period = [
        event
        for event in records
        if event.timestamp is not None and cutoff <= event.timestamp <= latest
    ]
    seeds: list[FindingSeed] = []
    for event in in_period:
        seeds.extend(classify_event(event))
    seeds.extend(correlate_failed_logons(in_period))
    seeds = _upgrade_unremediated_defender(seeds, in_period)
    findings = group_seeds(seeds)
    return NodeResult.complete(
        node,
        findings,
        current_diagnostics,
        period_start=cutoff,
        period_end=latest,
        records_read=total_read,
        logs_seen=logs_seen,
        archives_seen=archives_seen,
    )
