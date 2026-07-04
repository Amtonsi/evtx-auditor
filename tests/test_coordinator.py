from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from zipfile import ZipFile

import pytest

from evtx_auditor.coordinator import AnalysisCancelled, AuditCoordinator
from evtx_auditor.models import EventRecord
from evtx_auditor.parser import FastEventMetadata, ScannedRecord


def _write_archive(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as handle:
        handle.writestr("System.evtx", b"fixture")


def _fake_reader(path, context, on_issue=None):
    yield EventRecord(
        node=context.node,
        archive=context.archive,
        log_file=context.log_file,
        channel="System",
        provider="Microsoft-Windows-Kernel-Power",
        event_id=41,
        level=1,
        timestamp=datetime(2026, 7, 2, tzinfo=timezone.utc),
        record_id=1,
        computer=context.node,
        task=63,
        opcode=0,
        keywords="",
        data={},
        rendered_message="Unexpected restart",
    )


def _fake_scanner(path, context, candidate_predicate, on_issue=None):
    event = next(_fake_reader(path, context, on_issue))
    yield ScannedRecord(
        FastEventMetadata(event.event_id, event.level, event.timestamp), event
    )
    yield ScannedRecord(
        FastEventMetadata(1, 4, event.timestamp), None
    )


def test_coordinator_continues_after_one_bad_archive(tmp_path: Path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    _write_archive(source / "GOOD" / "good.zip")
    bad = source / "BAD" / "bad.zip"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"broken")
    updates = []

    run = AuditCoordinator(
        event_reader=_fake_reader, progress=updates.append
    ).run(source, output, Event())

    statuses = {node.node: node.status.value for node in run.nodes}
    assert statuses["GOOD"] == "checked"
    assert statuses["BAD"] == "failed"
    assert run.report_path is not None
    assert run.report_path.exists()
    assert updates[-1].completed_nodes == 2


def test_cancel_removes_temporary_output(tmp_path: Path):
    cancelled = Event()
    cancelled.set()
    output = tmp_path / "out"

    with pytest.raises(AnalysisCancelled):
        AuditCoordinator().run(tmp_path, output, cancelled)

    assert not output.exists() or list(output.glob("*.tmp")) == []


def test_coordinator_counts_fast_scanned_non_candidates(tmp_path: Path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    _write_archive(source / "GOOD" / "good.zip")

    run = AuditCoordinator(record_scanner=_fake_scanner).run(
        source, output, Event()
    )

    assert run.nodes[0].records_read == 2
    assert run.nodes[0].critical_count == 1
