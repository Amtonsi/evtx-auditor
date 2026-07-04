from __future__ import annotations

import traceback
from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from evtx_auditor.coordinator import (
    AnalysisCancelled,
    AuditCoordinator,
)


class AnalysisWorker(QObject):
    progress = Signal(object)
    message = Signal(object)
    completed = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, source: Path, output: Path) -> None:
        super().__init__()
        self.source = source
        self.output = output
        self.cancel_event = Event()

    @Slot()
    def run(self) -> None:
        coordinator = AuditCoordinator(
            progress=self.progress.emit,
            message=self.message.emit,
        )
        try:
            result = coordinator.run(
                self.source, self.output, self.cancel_event
            )
        except AnalysisCancelled:
            self.cancelled.emit()
        except Exception:
            self.failed.emit(traceback.format_exc())
        else:
            self.completed.emit(result)

    @Slot()
    def cancel(self) -> None:
        self.cancel_event.set()

