from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

from .analyzer import analyze_events
from .archive import extract_event_logs
from .discovery import discover_archives, group_archives_by_node
from .legacy_evt import scan_evt
from .models import (
    AuditRun,
    Diagnostic,
    EventRecord,
    NodeResult,
)
from .parser import (
    EventContext,
    FastEventMetadata,
    ParseIssue,
    ScannedRecord,
    iter_evtx,
    scan_evtx,
)
from .report import render_report
from .rules import (
    is_candidate_event,
    is_candidate_metadata,
    requires_full_event_details,
)


@dataclass(frozen=True)
class ProgressUpdate:
    completed_nodes: int
    total_nodes: int
    node: str
    stage: str
    source: str


class AnalysisCancelled(RuntimeError):
    pass


EventReader = Callable[
    [Path, EventContext, Callable[[ParseIssue], None] | None],
    Iterator[EventRecord],
]
RecordScanner = Callable[
    [
        Path,
        EventContext,
        Callable[[int, int | None], bool],
        Callable[[ParseIssue], None] | None,
    ],
    Iterator[ScannedRecord],
]


class AuditCoordinator:
    def __init__(
        self,
        progress: Callable[[ProgressUpdate], None] | None = None,
        message: Callable[[Diagnostic], None] | None = None,
        event_reader: EventReader | None = None,
        record_scanner: RecordScanner = scan_evtx,
        legacy_record_scanner: RecordScanner = scan_evt,
    ) -> None:
        self.progress = progress or (lambda update: None)
        self.message = message or (lambda diagnostic: None)
        self.event_reader = event_reader
        self.record_scanner = record_scanner
        self.legacy_record_scanner = legacy_record_scanner

    @staticmethod
    def _check_cancelled(cancelled: Event) -> None:
        if cancelled.is_set():
            raise AnalysisCancelled("Анализ отменён пользователем")

    def _emit_diagnostic(
        self, diagnostics: list[Diagnostic], diagnostic: Diagnostic
    ) -> None:
        diagnostics.append(diagnostic)
        self.message(diagnostic)

    def _analyze_node(
        self,
        node: str,
        sources,
        completed_nodes: int,
        total_nodes: int,
        cancelled: Event,
    ) -> tuple[NodeResult, int]:
        diagnostics: list[Diagnostic] = []
        candidates: list[EventRecord] = []
        latest_timestamp = None
        records_read = 0
        logs_seen: list[str] = []
        extracted_log_count = 0

        with TemporaryDirectory(prefix="evtx-auditor-") as temporary:
            temporary_root = Path(temporary)
            for archive_index, source in enumerate(sources, start=1):
                self._check_cancelled(cancelled)
                self.progress(
                    ProgressUpdate(
                        completed_nodes,
                        total_nodes,
                        node,
                        "extracting",
                        source.path.name,
                    )
                )
                destination = temporary_root / f"archive-{archive_index}"
                try:
                    logs = extract_event_logs(source.path, destination)
                except Exception as error:
                    self._emit_diagnostic(
                        diagnostics,
                        Diagnostic.error(
                            source.path.name,
                            f"Архив не обработан: {error}",
                        ),
                    )
                    continue
                if not logs:
                    self._emit_diagnostic(
                        diagnostics,
                        Diagnostic.error(
                            source.path.name, "В архиве нет файлов EVTX/EVT"
                        ),
                    )
                    continue

                for log_path in logs:
                    self._check_cancelled(cancelled)
                    extracted_log_count += 1
                    logs_seen.append(log_path.name)
                    self.progress(
                        ProgressUpdate(
                            completed_nodes,
                            total_nodes,
                            node,
                            "parsing",
                            log_path.name,
                        )
                    )

                    def on_issue(issue: ParseIssue) -> None:
                        self._emit_diagnostic(
                            diagnostics,
                            Diagnostic.warning(
                                log_path.name, str(issue)
                            ),
                        )

                    context = EventContext(
                        node=node,
                        archive=source.path.name,
                        log_file=log_path.name,
                    )
                    try:
                        if self.event_reader is not None:
                            scanned_records = (
                                ScannedRecord(
                                    FastEventMetadata(
                                        event.event_id,
                                        event.level,
                                        event.timestamp,
                                    ),
                                    event
                                    if is_candidate_event(event)
                                    else None,
                                )
                                for event in self.event_reader(
                                    log_path, context, on_issue
                                )
                            )
                        else:
                            scanner = (
                                self.legacy_record_scanner
                                if log_path.suffix.casefold() == ".evt"
                                else self.record_scanner
                            )
                            scanned_records = scanner(
                                log_path,
                                context,
                                is_candidate_metadata,
                                on_issue,
                                always_render_predicate=(
                                    requires_full_event_details
                                ),
                            )
                        for scanned in scanned_records:
                            records_read += 1
                            if records_read % 500 == 0:
                                self._check_cancelled(cancelled)
                            metadata = scanned.metadata
                            if (
                                metadata.timestamp is not None
                                and (
                                    latest_timestamp is None
                                    or metadata.timestamp > latest_timestamp
                                )
                            ):
                                latest_timestamp = metadata.timestamp
                            event = scanned.event
                            if event is None:
                                continue
                            if event.computer and (
                                event.computer.casefold() != node.casefold()
                            ):
                                if not any(
                                    item.source == log_path.name
                                    and "имя компьютера" in item.message
                                    for item in diagnostics
                                ):
                                    self._emit_diagnostic(
                                        diagnostics,
                                        Diagnostic.warning(
                                            log_path.name,
                                            "Поле Computer события отличается "
                                            f"от имени узла: {event.computer}",
                                        ),
                                    )
                            candidates.append(event)
                    except Exception as error:
                        self._emit_diagnostic(
                            diagnostics,
                            Diagnostic.error(
                                log_path.name,
                                f"Журнал прочитан не полностью: {error}",
                            ),
                        )

        archives_seen = tuple(source.path.name for source in sources)
        if extracted_log_count == 0:
            if not diagnostics:
                diagnostics.append(
                    Diagnostic.error(node, "Не найдено доступных журналов")
                )
            return (
                NodeResult.failed(
                    node,
                    diagnostics,
                    records_read=records_read,
                    logs_seen=tuple(logs_seen),
                    archives_seen=archives_seen,
                ),
                extracted_log_count,
            )
        return (
            analyze_events(
                node,
                candidates,
                diagnostics,
                tuple(logs_seen),
                latest_timestamp=latest_timestamp,
                records_read=records_read,
                archives_seen=archives_seen,
            ),
            extracted_log_count,
        )

    def run(
        self, source_root: Path, output_dir: Path, cancelled: Event
    ) -> AuditRun:
        self._check_cancelled(cancelled)
        sources = discover_archives(source_root)
        if not sources:
            raise ValueError("В выбранной папке не найдены ZIP-архивы")
        grouped = group_archives_by_node(sources)
        total_nodes = len(grouped)
        results: list[NodeResult] = []
        evtx_count = 0

        for completed, (node, node_sources) in enumerate(
            grouped.items(), start=1
        ):
            self._check_cancelled(cancelled)
            result, node_evtx_count = self._analyze_node(
                node,
                node_sources,
                completed - 1,
                total_nodes,
                cancelled,
            )
            results.append(result)
            evtx_count += node_evtx_count
            self.progress(
                ProgressUpdate(
                    completed,
                    total_nodes,
                    node,
                    "completed",
                    node,
                )
            )

        self._check_cancelled(cancelled)
        created_at = datetime.now(timezone.utc)
        run = AuditRun(
            source_root=source_root.resolve(),
            created_at=created_at,
            nodes=tuple(results),
            metadata={
                "archive_count": len(sources),
                "evtx_count": evtx_count,
            },
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        report_name = (
            f"EVTX_Audit_{created_at.astimezone():%Y-%m-%d_%H-%M-%S}.html"
        )
        report_path = output_dir / report_name
        temporary_path = output_dir / f".{report_name}.tmp"
        try:
            temporary_path.write_text(
                render_report(run), encoding="utf-8", newline="\n"
            )
            self._check_cancelled(cancelled)
            temporary_path.replace(report_path)
        finally:
            temporary_path.unlink(missing_ok=True)
        return replace(run, report_path=report_path)
