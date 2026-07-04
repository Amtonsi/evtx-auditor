from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from evtx_auditor.coordinator import AuditCoordinator, ProgressUpdate
from evtx_auditor.models import Diagnostic
from evtx_auditor.verification import (
    create_source_zip,
    inventory_archives,
    is_offline_html,
    sha256_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Проверка EVTX Аудитора на реальном наборе архивов."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    return parser.parse_args()


def tracked_files(root: Path) -> list[str]:
    process = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [
        value.decode("utf-8")
        for value in process.stdout.split(b"\0")
        if value
    ]


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    source = args.source.resolve()
    output = args.output.resolve()
    exe = args.exe.resolve()
    output.mkdir(parents=True, exist_ok=True)

    print("Вычисление исходных SHA-256...")
    before = inventory_archives(source)
    if before["archive_count"] != 22:
        raise RuntimeError(
            f"Ожидалось 22 архива, обнаружено {before['archive_count']}"
        )
    if before["evtx_count"] != 66:
        raise RuntimeError(
            f"Ожидалось 66 EVTX, обнаружено {before['evtx_count']}"
        )

    def progress(update: ProgressUpdate) -> None:
        print(
            f"[{update.completed_nodes}/{update.total_nodes}] "
            f"{update.node}: {update.stage} · {update.source}",
            flush=True,
        )

    def message(diagnostic: Diagnostic) -> None:
        if diagnostic.level.value != "info":
            print(
                f"  {diagnostic.level.value.upper()} "
                f"{diagnostic.source}: {diagnostic.message}",
                flush=True,
            )

    print("Анализ 22 узлов...")
    run = AuditCoordinator(progress=progress, message=message).run(
        source, output, Event()
    )
    if run.report_path is None:
        raise RuntimeError("Координатор не создал HTML-отчёт")

    print("Повторная проверка SHA-256 исходных архивов...")
    after = inventory_archives(source)
    hashes_unchanged = before["hashes"] == after["hashes"]
    if not hashes_unchanged:
        raise RuntimeError("Хеши исходных архивов изменились")

    report_text = run.report_path.read_text(encoding="utf-8")
    if not is_offline_html(report_text):
        raise RuntimeError("HTML содержит внешнюю сетевую ссылку")
    missing_nodes = [
        node.node for node in run.nodes if node.node not in report_text
    ]
    if missing_nodes:
        raise RuntimeError(
            "В HTML отсутствуют узлы: " + ", ".join(missing_nodes)
        )

    copied_exe = output / "EVTXAuditor.exe"
    shutil.copy2(exe, copied_exe)
    self_test = subprocess.run(
        [str(copied_exe), "--self-test"],
        timeout=180,
        check=False,
    )
    if self_test.returncode != 0:
        raise RuntimeError(
            f"Self-test EXE завершился кодом {self_test.returncode}"
        )

    source_zip = output / "EVTXAuditor-Source.zip"
    create_source_zip(root, source_zip, tracked_files(root))

    verification = {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "archive_count": before["archive_count"],
        "evtx_count": before["evtx_count"],
        "source_hashes_unchanged": hashes_unchanged,
        "source_hashes": before["hashes"],
        "report": {
            "path": str(run.report_path),
            "sha256": sha256_file(run.report_path),
            "offline": True,
        },
        "executable": {
            "path": str(copied_exe),
            "sha256": sha256_file(copied_exe),
            "self_test_exit_code": self_test.returncode,
        },
        "source_archive": {
            "path": str(source_zip),
            "sha256": sha256_file(source_zip),
        },
        "nodes": [
            {
                "name": node.node,
                "status": node.status.value,
                "records_read": node.records_read,
                "critical": node.critical_count,
                "errors": node.error_count,
                "security": node.security_count,
                "diagnostics": [
                    {
                        "level": item.level.value,
                        "source": item.source,
                        "message": item.message,
                    }
                    for item in node.diagnostics
                ],
            }
            for node in run.nodes
        ],
    }
    verification_path = output / "verification.json"
    verification_path.write_text(
        json.dumps(verification, ensure_ascii=False, indent=2),
        encoding="utf-8",
        newline="\n",
    )
    print(f"Отчёт: {run.report_path}")
    print(f"EXE: {copied_exe}")
    print(f"Исходники: {source_zip}")
    print(f"Проверка: {verification_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
