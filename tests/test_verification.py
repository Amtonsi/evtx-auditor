from pathlib import Path
from zipfile import ZipFile

from evtx_auditor.verification import (
    create_source_zip,
    inventory_archives,
    is_offline_html,
    sha256_file,
)


def test_inventory_hashes_archives_and_counts_evtx(tmp_path: Path):
    node = tmp_path / "HOST"
    node.mkdir()
    archive = node / "events.zip"
    with ZipFile(archive, "w") as handle:
        handle.writestr("Application.evtx", b"one")
        handle.writestr("System.evtx", b"two")

    result = inventory_archives(tmp_path)

    assert result["archive_count"] == 1
    assert result["evtx_count"] == 2
    assert result["hashes"][str(archive)] == sha256_file(archive)


def test_offline_html_rejects_network_urls():
    assert is_offline_html("<html><p>offline</p></html>") is True
    assert is_offline_html("<script src='https://example.test/a.js'></script>") is False


def test_source_zip_contains_only_requested_files(tmp_path: Path):
    (tmp_path / "README.md").write_text("readme", encoding="utf-8")
    (tmp_path / "secret.evtx").write_bytes(b"secret")
    destination = tmp_path / "source.zip"

    create_source_zip(tmp_path, destination, ["README.md"])

    with ZipFile(destination) as archive:
        assert archive.namelist() == ["README.md"]
