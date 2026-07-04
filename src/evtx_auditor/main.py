from __future__ import annotations

import sys
from importlib import resources
from pathlib import Path


def self_test() -> int:
    from Evtx.Evtx import Evtx
    from PySide6.QtCore import qVersion

    from evtx_auditor.report import render_report

    assert Evtx is not None
    assert qVersion()
    assert render_report is not None
    assert (
        resources.files("evtx_auditor")
        .joinpath("report_template.html")
        .is_file()
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in values:
        return self_test()

    from PySide6.QtWidgets import QApplication

    from evtx_auditor.gui.main_window import MainWindow

    app = QApplication([sys.argv[0], *values])
    app.setApplicationName("EVTX Аудитор")
    app.setOrganizationName("Local Audit")
    window = MainWindow(
        default_source=Path(r"C:\Users\impal\Downloads\АУДИТ 2"),
        default_output=Path.home()
        / "Documents"
        / "EVTX Auditor Reports",
    )
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
