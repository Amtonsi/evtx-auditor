# Windows EVTX Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Создать автономное приложение PySide6, которое анализирует последние 30 дней событий из ZIP-архивов EVTX, выявляет Critical, Error и события ИБ, формирует единый подробный HTML и поставляется как Windows EXE с исходным кодом.

**Architecture:** Ядро не зависит от GUI: discovery находит архивы, archive безопасно извлекает EVTX, parser потоково нормализует XML, rules классифицирует кандидаты, analyzer рассчитывает период и корреляции, report создаёт автономный HTML. Coordinator соединяет этапы и сообщает прогресс; PySide6 запускает его в отдельном QThread.

**Tech Stack:** Python 3.14, PySide6 6.11.1, python-evtx 0.8.1, pytest 9.1.1, PyInstaller 6.21.0, стандартные `zipfile`, `xml.etree.ElementTree`, `dataclasses`, `pathlib`, `tempfile`, `json`.

---

## File Structure

```text
.
├── .gitignore
├── README.md
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── EVTXAuditor.spec
├── scripts/
│   ├── build.ps1
│   └── verify_real_archives.py
├── src/evtx_auditor/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── discovery.py
│   ├── archive.py
│   ├── parser.py
│   ├── rules.py
│   ├── analyzer.py
│   ├── coordinator.py
│   ├── report.py
│   ├── report_template.html
│   └── gui/
│       ├── __init__.py
│       ├── worker.py
│       └── main_window.py
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── critical_event.xml
    │   ├── security_4625.xml
    │   └── partial_event.xml
    ├── test_models.py
    ├── test_discovery_archive.py
    ├── test_parser.py
    ├── test_rules.py
    ├── test_analyzer.py
    ├── test_report.py
    ├── test_coordinator.py
    └── test_gui.py
```

Each production file has one responsibility. `models.py` is the shared contract; no module imports GUI except modules under `gui/`.

---

### Task 1: Initialize the project and dependency gate

**Files:**
- Create: `.gitignore`
- Create: `pyproject.toml`
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `src/evtx_auditor/__init__.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Initialize local version control and ignore generated artifacts**

Run:

```powershell
git init
```

Create `.gitignore` with:

```gitignore
.venv/
.pytest_cache/
__pycache__/
*.py[cod]
build/
dist/
outputs/
work/
.superpowers/
```

Expected: `git status --short` does not show `.superpowers`, `outputs`, or `work`.

- [ ] **Step 2: Pin the verified dependency versions**

Create `requirements.txt`:

```text
PySide6==6.11.1
python-evtx==0.8.1
```

Create `requirements-dev.txt`:

```text
-r requirements.txt
pytest==9.1.1
pyinstaller==6.21.0
```

Create `pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=80"]
build-backend = "setuptools.build_meta"

[project]
name = "evtx-auditor"
version = "1.0.0"
description = "Offline Windows EVTX archive auditor"
requires-python = ">=3.11"
dependencies = [
  "PySide6==6.11.1",
  "python-evtx==0.8.1",
]

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
evtx_auditor = ["report_template.html"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
addopts = "-ra"
```

- [ ] **Step 3: Write the first failing package test**

Create `tests/test_models.py`:

```python
def test_package_exposes_version():
    import evtx_auditor

    assert evtx_auditor.__version__ == "1.0.0"
```

- [ ] **Step 4: Run the test and verify RED**

Run:

```powershell
python -m pytest tests/test_models.py -v
```

Expected: FAIL because `evtx_auditor` or `__version__` does not exist.

- [ ] **Step 5: Add the minimal package file and install dependencies**

Create `src/evtx_auditor/__init__.py`:

```python
"""Offline Windows event-log archive auditor."""

__version__ = "1.0.0"
```

Run:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest tests/test_models.py -v
```

Expected: `1 passed`.

- [ ] **Step 6: Commit the scaffold**

```powershell
git add .gitignore pyproject.toml requirements.txt requirements-dev.txt src tests
git commit -m "chore: initialize EVTX auditor project"
```

---

### Task 2: Define stable domain models

**Files:**
- Create: `src/evtx_auditor/models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Write failing tests for event, finding, diagnostic, and node status**

Append to `tests/test_models.py`:

```python
from datetime import datetime, timezone

from evtx_auditor.models import (
    Diagnostic,
    EventRecord,
    Finding,
    FindingCategory,
    NodeResult,
    NodeStatus,
)


def test_node_with_findings_is_checked():
    event = EventRecord(
        node="HOST-1",
        archive="host.zip",
        log_file="System.evtx",
        channel="System",
        provider="Microsoft-Windows-Kernel-Power",
        event_id=41,
        level=1,
        timestamp=datetime(2026, 7, 2, tzinfo=timezone.utc),
        record_id=100,
        computer="HOST-1",
        task=None,
        opcode=None,
        keywords="",
        data={},
        rendered_message=None,
    )
    finding = Finding.from_events(
        category=FindingCategory.CRITICAL,
        priority=100,
        title="Аварийная перезагрузка",
        explanation="Система завершила работу некорректно.",
        recommendation="Проверить питание и дампы.",
        grouping_key=("HOST-1", "System", "Kernel-Power", "41"),
        events=[event],
    )
    result = NodeResult.complete("HOST-1", [finding], [Diagnostic.info("System.evtx", "ok")])

    assert result.status is NodeStatus.CHECKED
    assert result.critical_count == 1
    assert finding.first_seen == event.timestamp
    assert finding.last_seen == event.timestamp
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
python -m pytest tests/test_models.py::test_node_with_findings_is_checked -v
```

Expected: FAIL because `evtx_auditor.models` does not exist.

- [ ] **Step 3: Implement the domain contracts**

Create `src/evtx_auditor/models.py` with:

```python
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
    def info(cls, source: str, message: str) -> "Diagnostic":
        return cls(DiagnosticLevel.INFO, source, message)

    @classmethod
    def warning(cls, source: str, message: str) -> "Diagnostic":
        return cls(DiagnosticLevel.WARNING, source, message)

    @classmethod
    def error(cls, source: str, message: str) -> "Diagnostic":
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
    ) -> "Finding":
        timestamps = sorted(event.timestamp for event in events if event.timestamp is not None)
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

    @classmethod
    def complete(
        cls,
        node: str,
        findings: list[Finding],
        diagnostics: list[Diagnostic],
        **values: Any,
    ) -> "NodeResult":
        has_errors = any(item.level is DiagnosticLevel.ERROR for item in diagnostics)
        if has_errors:
            status = NodeStatus.PARTIAL
        elif findings:
            status = NodeStatus.CHECKED
        else:
            status = NodeStatus.NO_FINDINGS
        return cls(node, status, tuple(findings), tuple(diagnostics), **values)

    @property
    def critical_count(self) -> int:
        return sum(item.category is FindingCategory.CRITICAL for item in self.findings)

    @property
    def error_count(self) -> int:
        return sum(item.category is FindingCategory.ERROR for item in self.findings)

    @property
    def security_count(self) -> int:
        return sum(item.category is FindingCategory.SECURITY for item in self.findings)


@dataclass(frozen=True)
class AuditRun:
    source_root: Path
    created_at: datetime
    nodes: tuple[NodeResult, ...]
    report_path: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

- [ ] **Step 4: Run all model tests**

Run:

```powershell
python -m pytest tests/test_models.py -v
```

Expected: all model tests PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/evtx_auditor/models.py tests/test_models.py
git commit -m "feat: add audit domain models"
```

---

### Task 3: Discover archives and extract EVTX safely

**Files:**
- Create: `src/evtx_auditor/discovery.py`
- Create: `src/evtx_auditor/archive.py`
- Create: `tests/test_discovery_archive.py`

- [ ] **Step 1: Write failing discovery and ZIP traversal tests**

Create `tests/test_discovery_archive.py`:

```python
from pathlib import Path
from zipfile import ZipFile

import pytest

from evtx_auditor.archive import ArchiveLimitError, UnsafeArchiveError, extract_evtx
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
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_discovery_archive.py -v
```

Expected: collection FAIL because discovery and archive modules do not exist.

- [ ] **Step 3: Implement deterministic discovery**

Create `src/evtx_auditor/discovery.py`:

```python
from collections import defaultdict
from pathlib import Path

from .models import ArchiveSource


def discover_archives(root: Path) -> list[ArchiveSource]:
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    return [
        ArchiveSource(path=path, node_hint=path.parent.name)
        for path in sorted(root.rglob("*.zip"), key=lambda item: str(item).casefold())
    ]


def group_archives_by_node(
    sources: list[ArchiveSource],
) -> dict[str, list[ArchiveSource]]:
    grouped: dict[str, list[ArchiveSource]] = defaultdict(list)
    for source in sources:
        grouped[source.node_hint].append(source)
    return dict(sorted(grouped.items(), key=lambda item: item[0].casefold()))
```

- [ ] **Step 4: Implement guarded extraction**

Create `src/evtx_auditor/archive.py` with:

```python
from pathlib import Path, PurePosixPath
from shutil import copyfileobj
from zipfile import BadZipFile, ZipFile, ZipInfo

MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_ARCHIVE_SIZE = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 1000


class UnsafeArchiveError(ValueError):
    pass


class ArchiveLimitError(ValueError):
    pass


def _validated_relative_path(info: ZipInfo) -> Path:
    value = PurePosixPath(info.filename.replace("\\", "/"))
    if value.is_absolute() or ".." in value.parts or ":" in value.parts[0]:
        raise UnsafeArchiveError(info.filename)
    return Path(*value.parts)


def extract_evtx(archive_path: Path, destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    extracted: list[Path] = []
    with ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ArchiveLimitError(f"Слишком много записей ZIP: {len(entries)}")
        selected = [info for info in entries if not info.is_dir() and info.filename.lower().endswith(".evtx")]
        total_size = sum(info.file_size for info in selected)
        if total_size > MAX_ARCHIVE_SIZE:
            raise ArchiveLimitError(f"Распакованный объём превышает {MAX_ARCHIVE_SIZE}")
        for info in selected:
            if info.file_size > MAX_ENTRY_SIZE:
                raise ArchiveLimitError(f"EVTX слишком велик: {info.filename}")
            relative = _validated_relative_path(info)
            target = (destination_root / relative).resolve()
            if not target.is_relative_to(destination_root):
                raise UnsafeArchiveError(info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as output:
                copyfileobj(source, output, length=1024 * 1024)
            extracted.append(target)
    return sorted(extracted, key=lambda item: item.name.casefold())
```

- [ ] **Step 5: Run extraction tests**

Run:

```powershell
python -m pytest tests/test_discovery_archive.py -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/evtx_auditor/discovery.py src/evtx_auditor/archive.py tests/test_discovery_archive.py
git commit -m "feat: discover and safely extract EVTX archives"
```

---

### Task 4: Parse EVTX XML into normalized records

**Files:**
- Create: `src/evtx_auditor/parser.py`
- Create: `tests/fixtures/critical_event.xml`
- Create: `tests/fixtures/security_4625.xml`
- Create: `tests/fixtures/partial_event.xml`
- Create: `tests/test_parser.py`

- [ ] **Step 1: Add realistic XML fixtures**

`critical_event.xml` must contain Event ID 41, Level 1, `Kernel-Power`, UTC `SystemTime`, Record ID, Computer, Channel, Keywords and EventData.

`security_4625.xml` must contain Event ID 4625 with `TargetUserName`, `IpAddress`, `LogonType`, `Status` and `SubStatus`.

`partial_event.xml` must omit TimeCreated and EventRecordID while remaining valid XML.

- [ ] **Step 2: Write failing parser tests**

Create `tests/test_parser.py`:

```python
from pathlib import Path

from evtx_auditor.parser import EventContext, parse_event_xml

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_system_and_event_data():
    event = parse_event_xml(
        (FIXTURES / "security_4625.xml").read_text(encoding="utf-8"),
        EventContext("NEW-OPER-4", "events.zip", "Security.evtx"),
    )

    assert event.node == "NEW-OPER-4"
    assert event.channel == "Security"
    assert event.event_id == 4625
    assert event.data["TargetUserName"] == "operator"
    assert event.data["IpAddress"] == "192.168.10.24"
    assert event.timestamp is not None


def test_missing_optional_fields_become_warnings():
    event = parse_event_xml(
        (FIXTURES / "partial_event.xml").read_text(encoding="utf-8"),
        EventContext("HOST", "events.zip", "System.evtx"),
    )

    assert event.timestamp is None
    assert event.record_id is None
    assert "missing_timestamp" in event.parse_warnings
```

- [ ] **Step 3: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_parser.py -v
```

Expected: FAIL because parser module does not exist.

- [ ] **Step 4: Implement namespace-safe XML parsing and EVTX iteration**

Create `src/evtx_auditor/parser.py` with these public contracts:

```python
@dataclass(frozen=True)
class EventContext:
    node: str
    archive: str
    log_file: str


def parse_event_xml(xml_text: str, context: EventContext) -> EventRecord:
    """Parse System, EventData, UserData and RenderingInfo without resolving providers."""


def iter_evtx(path: Path, context: EventContext) -> Iterator[EventRecord]:
    """Yield records from Evtx(path).records(); skip malformed records through ParseIssue."""
```

Implementation requirements:

- use `xml.etree.ElementTree.fromstring`;
- match tags by local name so default namespaces do not affect parsing;
- parse `SystemTime` with `Z` as UTC;
- preserve duplicate unnamed `<Data>` fields as `Data_1`, `Data_2`;
- flatten UserData paths into stable dotted keys;
- return warnings for absent timestamp, channel, provider and record ID;
- expose malformed-record errors as a typed `ParseIssue` containing record index and message.

- [ ] **Step 5: Run parser tests**

Run:

```powershell
python -m pytest tests/test_parser.py -v
```

Expected: all parser tests PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/evtx_auditor/parser.py tests/fixtures tests/test_parser.py
git commit -m "feat: normalize archived EVTX records"
```

---

### Task 5: Implement the security and severity rule catalog

**Files:**
- Create: `src/evtx_auditor/rules.py`
- Create: `tests/test_rules.py`

- [ ] **Step 1: Write failing tests for native severity and catalog rules**

Create `tests/test_rules.py` using a small `make_event` factory. Cover:

```python
def test_native_level_one_is_critical():
    seeds = classify_event(make_event(event_id=41, level=1, channel="System"))
    assert seeds[0].category is FindingCategory.CRITICAL


def test_audit_log_clear_is_critical_even_without_level():
    seeds = classify_event(make_event(event_id=1102, level=None, channel="Security"))
    assert seeds[0].category is FindingCategory.CRITICAL
    assert "очищен" in seeds[0].title.lower()


def test_security_account_change_uses_specific_rule():
    event = make_event(
        event_id=4720,
        level=0,
        channel="Security",
        data={"TargetUserName": "new-user"},
    )
    seeds = classify_event(event)
    assert seeds[0].category is FindingCategory.SECURITY
    assert "new-user" in seeds[0].grouping_key


def test_4625_is_deferred_to_correlation():
    assert classify_event(make_event(event_id=4625, level=0, channel="Security")) == []
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_rules.py -v
```

Expected: FAIL because `classify_event` does not exist.

- [ ] **Step 3: Implement data-driven rules**

Create `src/evtx_auditor/rules.py` with immutable `RuleDefinition` records for:

- 104 and 1102 log clearing;
- 4719 audit-policy changes;
- 4720, 4726, 4728, 4732, 4738, 4740, 4756 and 4771;
- 7045 new services;
- Defender 1116, 1117, 5001 and 5007.

Implement:

```python
def classify_event(event: EventRecord) -> list[FindingSeed]:
    if event.event_id == 4625:
        return []
    rule = lookup_specific_rule(event)
    if rule is not None:
        return [seed_from_rule(event, rule)]
    if event.level == 1:
        return [generic_seed(event, FindingCategory.CRITICAL, 90)]
    if event.level == 2:
        return [generic_seed(event, FindingCategory.ERROR, 50)]
    return []
```

Specific rules take precedence over generic severity so one source event is not double-counted. Known rules include exact Russian titles, explanations, recommendations and meaningful grouping fields.

- [ ] **Step 4: Run all rule tests**

Run:

```powershell
python -m pytest tests/test_rules.py -v
```

Expected: all rule tests PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/evtx_auditor/rules.py tests/test_rules.py
git commit -m "feat: classify Windows errors and security events"
```

---

### Task 6: Calculate the 30-day window, correlate 4625, and group findings

**Files:**
- Create: `src/evtx_auditor/analyzer.py`
- Create: `tests/test_analyzer.py`

- [ ] **Step 1: Write failing period and grouping tests**

Create `tests/test_analyzer.py` with:

```python
from datetime import datetime, timedelta, timezone

from evtx_auditor.analyzer import analyze_events
from evtx_auditor.models import FindingCategory, NodeStatus


def test_period_is_relative_to_latest_event(make_event):
    latest = datetime(2026, 7, 2, tzinfo=timezone.utc)
    events = [
        make_event(event_id=1000, level=2, timestamp=latest - timedelta(days=31)),
        make_event(event_id=1001, level=2, timestamp=latest - timedelta(days=29)),
        make_event(event_id=1, level=4, timestamp=latest),
    ]

    result = analyze_events("HOST", events, diagnostics=[], logs_seen=("System.evtx",))

    assert result.period_start == latest - timedelta(days=30)
    assert [item.events[0].event_id for item in result.findings] == [1001]


def test_ten_failed_logons_in_fifteen_minutes_create_one_security_finding(make_event):
    started = datetime(2026, 7, 2, 9, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            event_id=4625,
            level=0,
            channel="Security",
            timestamp=started + timedelta(minutes=index),
            data={"TargetUserName": "operator", "IpAddress": "192.168.10.24"},
        )
        for index in range(10)
    ]

    result = analyze_events("HOST", events, diagnostics=[], logs_seen=("Security.evtx",))

    assert len(result.findings) == 1
    assert result.findings[0].category is FindingCategory.SECURITY
    assert len(result.findings[0].events) == 10


def test_nine_failed_logons_do_not_create_finding(make_event):
    events = [
        make_event(event_id=4625, level=0, data={"TargetUserName": "operator"})
        for _ in range(9)
    ]
    result = analyze_events("HOST", events, diagnostics=[], logs_seen=("Security.evtx",))
    assert result.status is NodeStatus.NO_FINDINGS
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_analyzer.py -v
```

Expected: FAIL because analyzer module does not exist.

- [ ] **Step 3: Implement filtering, correlation, and grouping**

Create `src/evtx_auditor/analyzer.py` with:

```python
ANALYSIS_DAYS = 30
FAILED_LOGON_THRESHOLD = 10
FAILED_LOGON_WINDOW = timedelta(minutes=15)


def analyze_events(
    node: str,
    events: Iterable[EventRecord],
    diagnostics: list[Diagnostic],
    logs_seen: tuple[str, ...],
) -> NodeResult:
    """Track latest time, filter to 30 days, correlate security events, and group seeds."""


def correlate_failed_logons(events: list[EventRecord]) -> list[FindingSeed]:
    """Use independent sliding windows by TargetUserName and IpAddress."""


def group_seeds(seeds: list[FindingSeed]) -> list[Finding]:
    """Group exact keys, sort events, and order findings by priority and last_seen."""
```

Behavior requirements:

- ignore candidates without a valid timestamp but add a warning diagnostic;
- calculate the cutoff only after the latest valid timestamp is known;
- keep 4625 windows separate for different users and source addresses;
- avoid emitting the same 4625 event twice when both user and address exceed the threshold;
- correlate Defender 1116 detection with subsequent 1117 remediation by threat identifier;
- group ordinary seeds by their complete grouping key;
- mark any node with error diagnostics as `partial`;
- never convert incomplete data into `no_findings`.

- [ ] **Step 4: Run analyzer tests**

Run:

```powershell
python -m pytest tests/test_analyzer.py -v
```

Expected: all analyzer tests PASS.

- [ ] **Step 5: Run the complete core suite**

Run:

```powershell
python -m pytest tests/test_models.py tests/test_discovery_archive.py tests/test_parser.py tests/test_rules.py tests/test_analyzer.py -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/evtx_auditor/analyzer.py tests/test_analyzer.py tests/conftest.py
git commit -m "feat: aggregate thirty-day audit findings"
```

---

### Task 7: Generate the autonomous detailed HTML report

**Files:**
- Create: `src/evtx_auditor/report.py`
- Create: `src/evtx_auditor/report_template.html`
- Create: `tests/test_report.py`

- [ ] **Step 1: Write failing report tests**

Create `tests/test_report.py`:

```python
from pathlib import Path

from evtx_auditor.report import render_report


def test_report_is_offline_and_contains_each_node(sample_audit_run):
    html = render_report(sample_audit_run)

    assert "40010-SRV-04B" in html
    assert "NEW-OPER-4" in html
    assert "https://" not in html
    assert "http://" not in html
    assert 'id="report-data"' in html
    assert "Приоритет проверки узлов" in html
    assert "Диагностика обработки" in html


def test_report_escapes_event_content(sample_audit_run_with_script_text):
    html = render_report(sample_audit_run_with_script_text)

    assert "</script><script>alert(1)</script>" not in html
    assert "\\u003c/script\\u003e" in html
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_report.py -v
```

Expected: FAIL because report module and template do not exist.

- [ ] **Step 3: Implement safe report serialization**

Create `src/evtx_auditor/report.py` with:

```python
def report_payload(run: AuditRun) -> dict[str, object]:
    """Return JSON-compatible summaries, nodes, findings, evidence, and diagnostics."""


def safe_json(value: object) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render_report(run: AuditRun) -> str:
    template = resources.files("evtx_auditor").joinpath("report_template.html").read_text("utf-8")
    return template.replace("__REPORT_DATA__", safe_json(report_payload(run)))
```

- [ ] **Step 4: Build the approved HTML template**

Create `report_template.html` as one UTF-8 document containing:

- the approved blue/teal visual system;
- left navigation for summary, critical, security, nodes and quality control;
- report metadata and date range;
- search, severity filter and channel filter;
- summary metric cards;
- risk-sorted node table;
- node sections and grouped finding cards;
- expandable evidence and technical fields;
- recommendations;
- diagnostics for every archive and EVTX;
- responsive CSS;
- embedded JavaScript that reads only `#report-data`, uses `textContent`, and never fetches network resources.

Embed data only through:

```html
<script id="report-data" type="application/json">__REPORT_DATA__</script>
```

- [ ] **Step 5: Run report tests and open a fixture report**

Run:

```powershell
python -m pytest tests/test_report.py -v
```

Expected: all report tests PASS.

Generate a fixture HTML into `work/fixture-report.html` and inspect it in the in-app browser at desktop and narrow widths.

- [ ] **Step 6: Commit**

```powershell
git add src/evtx_auditor/report.py src/evtx_auditor/report_template.html tests/test_report.py
git commit -m "feat: render autonomous detailed HTML report"
```

---

### Task 8: Coordinate archives, cancellation, progress, and atomic output

**Files:**
- Create: `src/evtx_auditor/coordinator.py`
- Create: `tests/test_coordinator.py`

- [ ] **Step 1: Write failing coordinator tests**

Create `tests/test_coordinator.py`:

```python
from pathlib import Path
from threading import Event

from evtx_auditor.coordinator import AnalysisCancelled, AuditCoordinator


def test_coordinator_continues_after_one_bad_archive(tmp_path: Path, sample_archive_factory):
    source = tmp_path / "source"
    output = tmp_path / "output"
    sample_archive_factory(source / "GOOD" / "good.zip")
    bad = source / "BAD" / "bad.zip"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"broken")

    run = AuditCoordinator().run(source, output, Event())

    statuses = {node.node: node.status.value for node in run.nodes}
    assert statuses["GOOD"] in {"checked", "no_findings"}
    assert statuses["BAD"] == "failed"
    assert run.report_path is not None
    assert run.report_path.exists()


def test_cancel_removes_temporary_output(tmp_path: Path):
    cancelled = Event()
    cancelled.set()

    with pytest.raises(AnalysisCancelled):
        AuditCoordinator().run(tmp_path, tmp_path / "out", cancelled)

    assert list((tmp_path / "out").glob("*.tmp")) == []
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_coordinator.py -v
```

Expected: FAIL because coordinator module does not exist.

- [ ] **Step 3: Implement the coordinator**

Create `src/evtx_auditor/coordinator.py` with:

```python
@dataclass(frozen=True)
class ProgressUpdate:
    completed_nodes: int
    total_nodes: int
    node: str
    stage: str
    source: str


class AnalysisCancelled(RuntimeError):
    pass


class AuditCoordinator:
    def __init__(
        self,
        progress: Callable[[ProgressUpdate], None] | None = None,
        message: Callable[[Diagnostic], None] | None = None,
    ) -> None:
        self.progress = progress or (lambda update: None)
        self.message = message or (lambda diagnostic: None)

    def run(self, source_root: Path, output_dir: Path, cancelled: Event) -> AuditRun:
        """Discover, extract, parse, analyze each node, atomically write HTML, and clean temp files."""
```

Implementation requirements:

- group all archives belonging to the same node;
- use one `TemporaryDirectory` per node;
- call `cancelled.is_set()` between archives and every 500 records;
- convert bad ZIP, EVTX and XML failures into diagnostics;
- emit progress after discovery, extraction, each log and each node;
- write the report to a temporary file in `output_dir`;
- use `Path.replace` for the final timestamped report;
- call `webbrowser.open(report_path.as_uri())` only from GUI after successful completion, not from the core coordinator.

- [ ] **Step 4: Run coordinator tests**

Run:

```powershell
python -m pytest tests/test_coordinator.py -v
```

Expected: all coordinator tests PASS.

- [ ] **Step 5: Commit**

```powershell
git add src/evtx_auditor/coordinator.py tests/test_coordinator.py
git commit -m "feat: coordinate resilient archive analysis"
```

---

### Task 9: Build the responsive PySide6 desktop window

**Files:**
- Create: `src/evtx_auditor/gui/__init__.py`
- Create: `src/evtx_auditor/gui/worker.py`
- Create: `src/evtx_auditor/gui/main_window.py`
- Create: `src/evtx_auditor/main.py`
- Create: `tests/test_gui.py`

- [ ] **Step 1: Write failing offscreen GUI tests**

Create `tests/test_gui.py`:

```python
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from evtx_auditor.gui.main_window import MainWindow


def test_window_has_required_controls(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(default_source=tmp_path / "source", default_output=tmp_path / "out")

    assert window.windowTitle() == "EVTX Аудитор событий Windows"
    assert window.source_edit.text().endswith("source")
    assert window.start_button.text() == "Начать проверку"
    assert window.cancel_button.isEnabled() is False
    assert window.progress_bar.minimum() == 0
    window.close()


def test_start_validation_requires_source_directory(tmp_path: Path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(default_source=tmp_path / "missing", default_output=tmp_path / "out")

    assert window.validate_inputs() is False
    window.close()
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest tests/test_gui.py -v
```

Expected: FAIL because GUI modules do not exist.

- [ ] **Step 3: Implement the worker-thread boundary**

Create `gui/worker.py`:

```python
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
        coordinator = AuditCoordinator(self.progress.emit, self.message.emit)
        try:
            result = coordinator.run(self.source, self.output, self.cancel_event)
        except AnalysisCancelled:
            self.cancelled.emit()
        except Exception:
            self.failed.emit(traceback.format_exc())
        else:
            self.completed.emit(result)

    @Slot()
    def cancel(self) -> None:
        self.cancel_event.set()
```

- [ ] **Step 4: Implement the approved main window**

Create `gui/main_window.py` with:

- responsive form rows for source and output paths;
- four configuration cards;
- start and cancel buttons;
- `QProgressBar`;
- current node/stage label;
- read-only diagnostic `QPlainTextEdit`;
- result panel with report path, «Открыть отчёт» and «Открыть папку»;
- teal/blue Qt stylesheet matching the approved mockup;
- `QFileDialog` folder selection;
- input validation;
- QThread lifecycle cleanup;
- `QDesktopServices.openUrl(QUrl.fromLocalFile(...))` for opening report and folder.

The public test-facing members are `source_edit`, `output_edit`, `start_button`, `cancel_button`, `progress_bar`, `validate_inputs`, and `start_analysis`.

- [ ] **Step 5: Add the application entry point and self-test argument**

Create `main.py`:

```python
def self_test() -> int:
    from Evtx.Evtx import Evtx
    from PySide6.QtCore import qVersion
    from evtx_auditor.report import render_report

    assert Evtx is not None
    assert qVersion()
    assert render_report is not None
    return 0


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in values:
        return self_test()
    app = QApplication([sys.argv[0], *values])
    window = MainWindow(
        default_source=Path(r"C:\Users\impal\Downloads\АУДИТ 2"),
        default_output=Path.home() / "Documents" / "EVTX Auditor Reports",
    )
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Run GUI and full tests**

Run:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest -v
python -m evtx_auditor.main --self-test
```

Expected: all tests PASS and self-test exits with code 0.

- [ ] **Step 7: Perform an interactive GUI smoke test**

Run:

```powershell
python -m evtx_auditor.main
```

Verify source and output selection, responsive resizing, button state changes, progress updates, cancellation and opening a fixture report.

- [ ] **Step 8: Commit**

```powershell
git add src/evtx_auditor/gui src/evtx_auditor/main.py tests/test_gui.py
git commit -m "feat: add responsive PySide6 audit window"
```

---

### Task 10: Package a single Windows executable

**Files:**
- Create: `EVTXAuditor.spec`
- Create: `scripts/build.ps1`
- Modify: `README.md`

- [ ] **Step 1: Write the PyInstaller specification**

Create `EVTXAuditor.spec`:

```python
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

root = Path(SPECPATH)

a = Analysis(
    [str(root / "src" / "evtx_auditor" / "main.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[
        (
            str(root / "src" / "evtx_auditor" / "report_template.html"),
            "evtx_auditor",
        )
    ],
    hiddenimports=collect_submodules("Evtx"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="EVTXAuditor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
```

- [ ] **Step 2: Write a build script with verification gates**

Create `scripts/build.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$env:QT_QPA_PLATFORM = 'offscreen'
python -m pytest -v
python -m compileall -q src tests
python -m PyInstaller --noconfirm --clean EVTXAuditor.spec

$Exe = Join-Path $Root 'dist\EVTXAuditor.exe'
if (-not (Test-Path -LiteralPath $Exe)) {
    throw "EXE was not created: $Exe"
}

$Process = Start-Process -FilePath $Exe -ArgumentList '--self-test' -WindowStyle Hidden -PassThru -Wait
if ($Process.ExitCode -ne 0) {
    throw "EXE self-test failed with exit code $($Process.ExitCode)"
}

Get-FileHash -Algorithm SHA256 -LiteralPath $Exe
```

- [ ] **Step 3: Run the build**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

Expected:

- pytest reports zero failures;
- compileall exits 0;
- PyInstaller exits 0;
- `dist\EVTXAuditor.exe` exists;
- EXE self-test returns 0;
- SHA-256 is printed.

- [ ] **Step 4: Launch the packaged GUI**

Run:

```powershell
Start-Process -FilePath .\dist\EVTXAuditor.exe
```

Verify the main window opens, all controls render, no console window appears, and the application closes normally.

- [ ] **Step 5: Commit packaging**

```powershell
git add EVTXAuditor.spec scripts/build.ps1 README.md
git commit -m "build: package Windows EVTX auditor executable"
```

---

### Task 11: Verify all 22 real archives and prepare deliverables

**Files:**
- Create: `scripts/verify_real_archives.py`
- Modify: `README.md`
- Create in output step: `outputs/EVTXAuditor.exe`
- Create in output step: `outputs/EVTXAuditor-Source.zip`
- Create in output step: `outputs/EVTX_Audit_YYYY-MM-DD_HH-MM-SS.html`
- Create in output step: `outputs/verification.json`

- [ ] **Step 1: Implement the real-data verification script**

Create `scripts/verify_real_archives.py` to:

- hash every ZIP with SHA-256 before analysis;
- discover sources and assert 22 archives;
- inspect ZIP entries and assert 66 EVTX;
- run `AuditCoordinator` against the real source;
- hash every ZIP again and require exact equality;
- require every discovered node in the report;
- require no `http://` or `https://` in the report;
- write `verification.json` with counts, report path, EXE hash, source hashes and diagnostics.

The script accepts:

```text
--source "C:\Users\impal\Downloads\АУДИТ 2"
--output "C:\Users\impal\Documents\Codex\2026-07-04\new-chat\outputs"
--exe "C:\Users\impal\Documents\Codex\2026-07-04\new-chat\dist\EVTXAuditor.exe"
```

- [ ] **Step 2: Run fresh automated verification**

Run:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest -v
python -m compileall -q src tests scripts
```

Expected: zero test failures and compileall exit 0.

- [ ] **Step 3: Run the real archive analysis**

Run:

```powershell
python scripts\verify_real_archives.py `
  --source 'C:\Users\impal\Downloads\АУДИТ 2' `
  --output 'C:\Users\impal\Documents\Codex\2026-07-04\new-chat\outputs' `
  --exe 'C:\Users\impal\Documents\Codex\2026-07-04\new-chat\dist\EVTXAuditor.exe'
```

Expected:

- `archives = 22`;
- `evtx_files = 66`;
- `source_hashes_unchanged = true`;
- one HTML report exists;
- `verification.json` contains all 22 nodes;
- any unreadable input appears as a diagnostic instead of terminating the run.

- [ ] **Step 4: Visually inspect the generated report**

Open the generated HTML in the in-app browser. Verify:

- summary counts match node sections;
- navigation reaches every node;
- filters work;
- critical, error and security cards expand;
- source evidence and diagnostics are readable;
- nodes with no findings differ from nodes with incomplete data;
- desktop and narrow layouts remain usable.

- [ ] **Step 5: Smoke-test the EXE against a copied small fixture**

Launch `dist\EVTXAuditor.exe`, choose a fixture source, create a report, open it, and confirm the GUI remains responsive during processing.

- [ ] **Step 6: Finish README**

Document:

- purpose and supported inputs;
- exact GUI workflow;
- severity and 4625 threshold;
- 30-day calculation;
- interpretation of `checked`, `no_findings`, `partial` and `failed`;
- build and test commands;
- known limitation that provider descriptions may be unavailable in archived EVTX;
- privacy statement that no network requests are made.

- [ ] **Step 7: Create source ZIP and copy verified deliverables**

Create `outputs/EVTXAuditor-Source.zip` from tracked source files only, excluding `.git`, `.venv`, `build`, `dist`, `work`, `.superpowers`, caches and real EVTX data.

Copy the freshly verified `dist\EVTXAuditor.exe` to `outputs\EVTXAuditor.exe`.

Recalculate SHA-256 for the copied EXE and source ZIP and add both hashes to `outputs\verification.json`.

- [ ] **Step 8: Final requirements audit**

Compare every section of `docs/superpowers/specs/2026-07-04-windows-evtx-auditor-design.md` against implementation and verification evidence. Record any gap; do not mark complete while a required item remains unverified.

- [ ] **Step 9: Commit final documentation and verification script**

```powershell
git add README.md scripts/verify_real_archives.py
git commit -m "docs: add verified audit workflow and usage guide"
```

Do not commit generated EXE, real reports, verification hashes, or source archives unless the user explicitly asks for them in version control.

---

## Plan Self-Review

- Spec coverage: GUI, archive safety, EVTX parsing, 30-day window, severity rules, security correlations, detailed HTML, diagnostics, EXE, source delivery and real-data verification each map to an explicit task.
- Placeholder scan: no implementation step delegates unspecified error handling or testing; thresholds, file limits, APIs, commands and expected outcomes are explicit.
- Type consistency: `EventRecord`, `FindingSeed`, `Finding`, `NodeResult`, `AuditRun`, `Diagnostic`, `AuditCoordinator`, `ProgressUpdate` and GUI signal payloads use the same names throughout.
- Scope: the plan implements only local ZIP/EVTX analysis and offline reporting; remote collection and automatic remediation remain excluded.
