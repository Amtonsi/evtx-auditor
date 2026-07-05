# Legacy EVT Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Windows XP `.evt` support to the existing EVTX Auditor without creating a second application.

**Architecture:** Extend archive extraction to accept `.evt`, add a focused legacy parser that normalizes pywin32 classic event records into `EventRecord`, route each extracted log by suffix in the coordinator, and add XP security Event ID rules to the existing classifier.

**Tech Stack:** Python 3.14, PySide6, python-evtx, pywin32, pytest, PyInstaller.

---

### Task 1: Dependencies and archive extraction

- [ ] Add `pywin32==312` to runtime and dev requirements.
- [ ] Add failing tests proving ZIP extraction includes `.evt` and `.evtx`.
- [ ] Replace EVTX-only extraction naming with generic event-log extraction while preserving the old public alias for compatibility.

### Task 2: Legacy EVT parser

- [ ] Add failing tests using fake classic event objects.
- [ ] Implement `legacy_evt.py` with event type to EVTX level mapping and insertion-string capture.
- [ ] Implement `scan_evt()` with pywin32 import guarded so environments without pywin32 fail with a diagnostic, not at import time.

### Task 3: Coordinator routing

- [ ] Add failing coordinator test proving `.evt` files are routed to the legacy scanner.
- [ ] Route `.evtx` to `scan_evtx` and `.evt` to `scan_evt`.
- [ ] Count both formats in report metadata.

### Task 4: XP rules and report evidence

- [ ] Add failing tests for XP security Event IDs.
- [ ] Add rule definitions for XP audit clear, failed logons, user changes and group changes.
- [ ] Add `source_format` to `EventRecord` and report evidence.

### Task 5: Build and deliver

- [ ] Run full pytest and compileall.
- [ ] Run PyInstaller build and EXE self-test.
- [ ] Recreate `outputs` for the already checked 2-node sample.
- [ ] Commit code changes and report updated artifacts.
