import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from evtx_auditor.gui.main_window import MainWindow


def test_window_has_required_controls(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    source = tmp_path / "source"
    source.mkdir()
    window = MainWindow(
        default_source=source, default_output=tmp_path / "out"
    )

    assert window.windowTitle() == "EVTX Аудитор событий Windows"
    assert window.source_edit.text().endswith("source")
    assert window.start_button.text() == "Начать проверку"
    assert window.period_days_spin.value() == 30
    assert window.cancel_button.isEnabled() is False
    assert window.progress_bar.minimum() == 0
    window.close()


def test_input_fields_show_visible_guidance(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    source = tmp_path / "source"
    source.mkdir()
    window = MainWindow(
        default_source=source, default_output=tmp_path / "out"
    )

    assert (
        window.source_edit.placeholderText()
        == "Укажите папку с ZIP-архивами журналов Windows"
    )
    assert "Укажите папку" in window.source_hint.text()
    assert (
        window.output_edit.placeholderText()
        == "Укажите папку для сохранения HTML-отчёта"
    )
    assert "Укажите папку" in window.output_hint.text()
    assert window.period_days_spin.toolTip() == "Введите период анализа в днях"
    assert "Введите период анализа" in window.period_hint.text()
    window.close()


def test_running_state_changes_start_button_and_locks_period(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    source = tmp_path / "source"
    source.mkdir()
    window = MainWindow(
        default_source=source, default_output=tmp_path / "out"
    )

    window._set_running(True)

    assert window.start_button.text() == "Идёт сканирование..."
    assert window.start_button.property("running") is True
    assert window.start_button.isEnabled() is False
    assert window.period_days_spin.isEnabled() is False

    window._set_running(False)

    assert window.start_button.text() == "Начать проверку"
    assert window.start_button.property("running") is False
    assert window.period_days_spin.isEnabled() is True
    window.close()


def test_start_validation_requires_source_directory(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(
        default_source=tmp_path / "missing",
        default_output=tmp_path / "out",
    )

    assert window.validate_inputs() is False
    window.close()
