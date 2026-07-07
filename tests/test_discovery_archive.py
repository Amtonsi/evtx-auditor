from pathlib import Path
from zipfile import ZipFile

import pytest

from evtx_auditor.archive import (
    MAX_ENTRY_SIZE,
    UnsafeArchiveError,
    extract_event_logs,
    extract_evtx,
)
from evtx_auditor.discovery import discover_archives, group_archives_by_node


def test_discovers_archives_and_uses_parent_as_node(tmp_path: Path):
    node = tmp_path / "NEW-OPER-4"
    node.mkdir()
    archive = node / "2026-07-02_EventLogs_NEW-OPER-4.zip"
    archive.write_bytes(b"not opened during discovery")

    sources = discover_archives(tmp_path)

    assert [item.path for item in sources] == [archive]
    assert group_archives_by_node(sources)["NEW-OPER-4"][0].path == archive


def test_rejects_zip_path_traversal(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with ZipFile(archive, "w") as handle:
        handle.writestr("../System.evtx", b"data")

    with pytest.raises(UnsafeArchiveError):
        extract_evtx(archive, tmp_path / "extract")


def test_extracts_only_evtx(tmp_path: Path):
    archive = tmp_path / "good.zip"
    with ZipFile(archive, "w") as handle:
        handle.writestr("Application.evtx", b"application")
        handle.writestr("notes.txt", b"ignored")

    files = extract_evtx(archive, tmp_path / "extract")

    assert [item.name for item in files] == ["Application.evtx"]
    assert files[0].read_bytes() == b"application"


def test_extracts_evtx_and_legacy_evt(tmp_path: Path):
    archive = tmp_path / "mixed.zip"
    with ZipFile(archive, "w") as handle:
        handle.writestr("Application.evtx", b"application")
        handle.writestr("System.evt", b"legacy-system")
        handle.writestr("notes.txt", b"ignored")

    files = extract_event_logs(archive, tmp_path / "extract")

    assert [item.name for item in files] == ["Application.evtx", "System.evt"]
    assert files[1].read_bytes() == b"legacy-system"


def test_single_event_log_limit_allows_large_legacy_system_evt():
    assert MAX_ENTRY_SIZE >= 600 * 1024 * 1024
