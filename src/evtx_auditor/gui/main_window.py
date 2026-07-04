from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from evtx_auditor.models import AuditRun, Diagnostic
from evtx_auditor.gui.worker import AnalysisWorker


STYLE = """
QMainWindow, QWidget#root {
    background: #f3f6f9;
    color: #1c2939;
}
QFrame#header {
    background: #153d68;
    border-radius: 14px;
}
QLabel#headerTitle {
    color: white;
    font-size: 22px;
    font-weight: 700;
}
QLabel#headerSubtitle {
    color: #c6d7e8;
}
QFrame.card {
    background: white;
    border: 1px solid #dce3eb;
    border-radius: 12px;
}
QLabel.fieldLabel {
    color: #5f6d82;
    font-size: 11px;
    font-weight: 700;
}
QLineEdit, QPlainTextEdit {
    background: white;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 9px;
    selection-background-color: #218f82;
}
QLineEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #218f82;
}
QPushButton {
    min-height: 34px;
    padding: 0 14px;
    border: 1px solid #b9c7d8;
    border-radius: 8px;
    color: #153d68;
    background: white;
    font-weight: 700;
}
QPushButton:hover { background: #edf4f8; }
QPushButton:disabled { color: #9aa6b5; background: #eef1f4; }
QPushButton#startButton {
    min-height: 42px;
    color: white;
    background: #218f82;
    border: 0;
}
QPushButton#startButton:hover { background: #19796f; }
QPushButton#cancelButton {
    min-height: 42px;
    color: #a62e39;
    border-color: #e1aeb4;
}
QFrame.configCard {
    background: #e8eff6;
    border: 0;
    border-radius: 9px;
}
QLabel.configText {
    color: #36526f;
    font-size: 11px;
    font-weight: 600;
}
QProgressBar {
    min-height: 12px;
    border: 0;
    border-radius: 6px;
    background: #d9e2ed;
    text-align: center;
}
QProgressBar::chunk {
    border-radius: 6px;
    background: #32aa9d;
}
QLabel#statusLabel { color: #5f6d82; }
QLabel#resultPath {
    color: #17665d;
    font-weight: 600;
}
"""


def _card(layout) -> QFrame:
    frame = QFrame()
    frame.setProperty("class", "card")
    frame.setLayout(layout)
    return frame


class MainWindow(QMainWindow):
    def __init__(
        self,
        *,
        default_source: Path,
        default_output: Path,
    ) -> None:
        super().__init__()
        self.setWindowTitle("EVTX Аудитор событий Windows")
        self.setMinimumSize(820, 680)
        self.resize(980, 760)
        self.setStyleSheet(STYLE)
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None
        self._result: AuditRun | None = None

        root = QWidget()
        root.setObjectName("root")
        page = QVBoxLayout(root)
        page.setContentsMargins(22, 22, 22, 22)
        page.setSpacing(14)
        self.setCentralWidget(root)

        header = QFrame()
        header.setObjectName("header")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 17, 20, 17)
        title = QLabel("EVTX Аудитор событий Windows")
        title.setObjectName("headerTitle")
        subtitle = QLabel(
            "Проверка архивных журналов Critical, Error и событий ИБ"
        )
        subtitle.setObjectName("headerSubtitle")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        page.addWidget(header)

        source_layout = QGridLayout()
        source_layout.setContentsMargins(16, 14, 16, 14)
        source_layout.setHorizontalSpacing(9)
        source_label = QLabel("ПАПКА С АРХИВАМИ")
        source_label.setProperty("class", "fieldLabel")
        self.source_edit = QLineEdit(str(default_source))
        self.source_edit.setClearButtonEnabled(True)
        self.source_button = QPushButton("Выбрать")
        self.source_button.clicked.connect(self.choose_source)
        source_layout.addWidget(source_label, 0, 0, 1, 2)
        source_layout.addWidget(self.source_edit, 1, 0)
        source_layout.addWidget(self.source_button, 1, 1)

        output_label = QLabel("ПАПКА ДЛЯ ОТЧЁТА")
        output_label.setProperty("class", "fieldLabel")
        self.output_edit = QLineEdit(str(default_output))
        self.output_edit.setClearButtonEnabled(True)
        self.output_button = QPushButton("Выбрать")
        self.output_button.clicked.connect(self.choose_output)
        source_layout.addWidget(output_label, 2, 0, 1, 2)
        source_layout.addWidget(self.output_edit, 3, 0)
        source_layout.addWidget(self.output_button, 3, 1)
        source_layout.setColumnStretch(0, 1)
        page.addWidget(_card(source_layout))

        config_layout = QGridLayout()
        config_layout.setContentsMargins(0, 0, 0, 0)
        config_layout.setSpacing(8)
        config_values = (
            "✓ Последние 30 дней",
            "✓ Critical и Error",
            "✓ Опасные события ИБ",
            "✓ Единый автономный HTML",
        )
        for index, value in enumerate(config_values):
            item = QFrame()
            item.setProperty("class", "configCard")
            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(12, 10, 12, 10)
            label = QLabel(value)
            label.setProperty("class", "configText")
            item_layout.addWidget(label)
            config_layout.addWidget(item, index // 2, index % 2)
        page.addLayout(config_layout)

        action_layout = QHBoxLayout()
        self.start_button = QPushButton("Начать проверку")
        self.start_button.setObjectName("startButton")
        self.start_button.clicked.connect(self.start_analysis)
        self.cancel_button = QPushButton("Отменить")
        self.cancel_button.setObjectName("cancelButton")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_analysis)
        action_layout.addWidget(self.start_button, 3)
        action_layout.addWidget(self.cancel_button, 1)
        page.addLayout(action_layout)

        progress_layout = QVBoxLayout()
        progress_layout.setContentsMargins(16, 14, 16, 14)
        progress_layout.setSpacing(7)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.status_label = QLabel("Готово к проверке")
        self.status_label.setObjectName("statusLabel")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        page.addWidget(_card(progress_layout))

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText(
            "Здесь появятся сообщения об обработке архивов и журналов."
        )
        self.log_view.setMaximumBlockCount(3000)
        self.log_view.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        log_layout = QVBoxLayout()
        log_layout.setContentsMargins(16, 14, 16, 14)
        log_label = QLabel("ХОД ПРОВЕРКИ")
        log_label.setProperty("class", "fieldLabel")
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_view)
        page.addWidget(_card(log_layout), 1)

        self.result_frame = QFrame()
        self.result_frame.setProperty("class", "card")
        result_layout = QHBoxLayout(self.result_frame)
        result_layout.setContentsMargins(16, 12, 16, 12)
        self.result_path = QLabel()
        self.result_path.setObjectName("resultPath")
        self.result_path.setWordWrap(True)
        self.open_report_button = QPushButton("Открыть отчёт")
        self.open_report_button.clicked.connect(self.open_report)
        self.open_folder_button = QPushButton("Открыть папку")
        self.open_folder_button.clicked.connect(self.open_output_folder)
        result_layout.addWidget(self.result_path, 1)
        result_layout.addWidget(self.open_report_button)
        result_layout.addWidget(self.open_folder_button)
        self.result_frame.hide()
        page.addWidget(self.result_frame)

    def choose_source(self) -> None:
        value = QFileDialog.getExistingDirectory(
            self, "Выберите папку с ZIP-архивами", self.source_edit.text()
        )
        if value:
            self.source_edit.setText(value)

    def choose_output(self) -> None:
        value = QFileDialog.getExistingDirectory(
            self, "Выберите папку для HTML-отчёта", self.output_edit.text()
        )
        if value:
            self.output_edit.setText(value)

    def validate_inputs(self, show_message: bool = False) -> bool:
        source = Path(self.source_edit.text().strip())
        output = Path(self.output_edit.text().strip())
        message = ""
        if not source.is_dir():
            message = "Исходная папка не существует."
        elif not any(source.rglob("*.zip")):
            message = "В исходной папке не найдены ZIP-архивы."
        elif output.exists() and not output.is_dir():
            message = "Путь отчёта указывает не на папку."
        if message and show_message:
            QMessageBox.warning(self, "Проверьте параметры", message)
        return not message

    def _set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)
        self.source_edit.setEnabled(not running)
        self.output_edit.setEnabled(not running)
        self.source_button.setEnabled(not running)
        self.output_button.setEnabled(not running)

    def start_analysis(self) -> None:
        if self._thread is not None or not self.validate_inputs(True):
            return
        source = Path(self.source_edit.text().strip())
        output = Path(self.output_edit.text().strip())
        output.mkdir(parents=True, exist_ok=True)
        self.log_view.clear()
        self.result_frame.hide()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.status_label.setText("Поиск архивов…")
        self._set_running(True)

        thread = QThread(self)
        worker = AnalysisWorker(source, output)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.message.connect(self._on_message)
        worker.completed.connect(self._on_completed)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        worker.completed.connect(thread.quit)
        worker.cancelled.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_thread_finished)
        self._thread = thread
        self._worker = worker
        thread.start()

    def cancel_analysis(self) -> None:
        if self._worker is None:
            return
        self._worker.cancel()
        self.cancel_button.setEnabled(False)
        self.status_label.setText("Отмена после текущей записи…")

    def _on_progress(self, update) -> None:
        self.progress_bar.setRange(0, max(update.total_nodes, 1))
        self.progress_bar.setValue(update.completed_nodes)
        labels = {
            "extracting": "Распаковка",
            "parsing": "Чтение",
            "completed": "Завершён",
        }
        stage = labels.get(update.stage, update.stage)
        self.status_label.setText(
            f"{stage}: {update.node} · {update.source} · "
            f"{update.completed_nodes} из {update.total_nodes}"
        )

    def _on_message(self, diagnostic: Diagnostic) -> None:
        self.log_view.appendPlainText(
            f"[{diagnostic.level.value.upper()}] "
            f"{diagnostic.source}: {diagnostic.message}"
        )

    def _on_completed(self, run: AuditRun) -> None:
        self._result = run
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.status_label.setText(
            f"Проверка завершена: {len(run.nodes)} узлов"
        )
        if run.report_path is not None:
            self.result_path.setText(str(run.report_path))
            self.result_frame.show()
            self.open_report()

    def _on_cancelled(self) -> None:
        self.status_label.setText("Проверка отменена")
        self.log_view.appendPlainText("[INFO] Анализ отменён пользователем.")

    def _on_failed(self, details: str) -> None:
        self.status_label.setText("Проверка завершилась с ошибкой")
        self.log_view.appendPlainText(details)
        QMessageBox.critical(
            self,
            "Ошибка анализа",
            "Не удалось завершить анализ. Подробности сохранены в журнале окна.",
        )

    def _on_thread_finished(self) -> None:
        self._set_running(False)
        thread = self._thread
        self._thread = None
        self._worker = None
        if thread is not None:
            thread.deleteLater()

    def open_report(self) -> None:
        if self._result is None or self._result.report_path is None:
            return
        QDesktopServices.openUrl(
            QUrl.fromLocalFile(str(self._result.report_path))
        )

    def open_output_folder(self) -> None:
        output = Path(self.output_edit.text().strip())
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(output)))

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None and self._thread.isRunning():
            if self._worker is not None:
                self._worker.cancel()
            self._thread.quit()
            if not self._thread.wait(5000):
                self.status_label.setText(
                    "Дождитесь безопасной остановки анализа."
                )
                event.ignore()
                return
        event.accept()

