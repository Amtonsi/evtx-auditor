from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class FindingCategory(StrEnum):
    CRITICAL = "critical"
    ERROR = "error"
    SECURITY = "security"


class NodeStatus(StrEnum):
    CHECKED = "checked"
    NO_FINDINGS = "no_findings"
    PARTIAL = "partial"
    FAILED = "failed"


class DiagnosticLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class Diagnostic:
    level: DiagnosticLevel
    source: str
    message: str

    @classmethod
    def info(cls, source: str, message: str) -> Diagnostic:
        return cls(DiagnosticLevel.INFO, source, message)

    @classmethod
    def warning(cls, source: str, message: str) -> Diagnostic:
        return cls(DiagnosticLevel.WARNING, source, message)

    @classmethod
    def error(cls, source: str, message: str) -> Diagnostic:
        return cls(DiagnosticLevel.ERROR, source, message)


@dataclass(frozen=True)
class ArchiveSource:
    path: Path
    node_hint: str


@dataclass(frozen=True)
class EventRecord:
    node: str
    archive: str
    log_file: str
    channel: str
    provider: str
    event_id: int
    level: int | None
    timestamp: datetime | None
    record_id: int | None
    computer: str
    task: int | None
    opcode: int | None
    keywords: str
    data: dict[str, str]
    rendered_message: str | None
    parse_warnings: tuple[str, ...] = ()
    source_format: str = "EVTX"


@dataclass(frozen=True)
class FindingSeed:
    category: FindingCategory
    priority: int
    title: str
    explanation: str
    recommendation: str
    grouping_key: tuple[str, ...]
    event: EventRecord


@dataclass(frozen=True)
class Finding:
    category: FindingCategory
    priority: int
    title: str
    explanation: str
    recommendation: str
    grouping_key: tuple[str, ...]
    events: tuple[EventRecord, ...]
    first_seen: datetime | None
    last_seen: datetime | None

    @classmethod
    def from_events(
        cls,
        *,
        category: FindingCategory,
        priority: int,
        title: str,
        explanation: str,
        recommendation: str,
        grouping_key: tuple[str, ...],
        events: list[EventRecord],
    ) -> Finding:
        timestamps = sorted(
            event.timestamp for event in events if event.timestamp is not None
        )
        return cls(
            category=category,
            priority=priority,
            title=title,
            explanation=explanation,
            recommendation=recommendation,
            grouping_key=grouping_key,
            events=tuple(events),
            first_seen=timestamps[0] if timestamps else None,
            last_seen=timestamps[-1] if timestamps else None,
        )


@dataclass(frozen=True)
class NodeResult:
    node: str
    status: NodeStatus
    findings: tuple[Finding, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    period_start: datetime | None = None
    period_end: datetime | None = None
    records_read: int = 0
    logs_seen: tuple[str, ...] = ()
    archives_seen: tuple[str, ...] = ()

    @classmethod
    def complete(
        cls,
        node: str,
        findings: list[Finding],
        diagnostics: list[Diagnostic],
        **values: Any,
    ) -> NodeResult:
        has_errors = any(
            item.level is DiagnosticLevel.ERROR for item in diagnostics
        )
        if has_errors:
            status = NodeStatus.PARTIAL
        elif findings:
            status = NodeStatus.CHECKED
        else:
            status = NodeStatus.NO_FINDINGS
        return cls(
            node=node,
            status=status,
            findings=tuple(findings),
            diagnostics=tuple(diagnostics),
            **values,
        )

    @classmethod
    def failed(
        cls, node: str, diagnostics: list[Diagnostic], **values: Any
    ) -> NodeResult:
        return cls(
            node=node,
            status=NodeStatus.FAILED,
            diagnostics=tuple(diagnostics),
            **values,
        )

    @property
    def critical_count(self) -> int:
        return sum(
            item.category is FindingCategory.CRITICAL for item in self.findings
        )

    @property
    def error_count(self) -> int:
        return sum(item.category is FindingCategory.ERROR for item in self.findings)

    @property
    def security_count(self) -> int:
        return sum(
            item.category is FindingCategory.SECURITY for item in self.findings
        )


@dataclass(frozen=True)
class AuditRun:
    source_root: Path
    created_at: datetime
    nodes: tuple[NodeResult, ...]
    report_path: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
