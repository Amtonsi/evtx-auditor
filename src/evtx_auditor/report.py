from __future__ import annotations

import json
from importlib import resources
from typing import Any

from .models import AuditRun, EventRecord, Finding, NodeResult


def _iso(value):
    return value.isoformat() if value is not None else None


def _event_payload(event: EventRecord) -> dict[str, Any]:
    return {
        "archive": event.archive,
        "log_file": event.log_file,
        "source_format": getattr(event, "source_format", "EVTX"),
        "channel": event.channel,
        "provider": event.provider,
        "event_id": event.event_id,
        "level": event.level,
        "timestamp": _iso(event.timestamp),
        "record_id": event.record_id,
        "computer": event.computer,
        "task": event.task,
        "opcode": event.opcode,
        "keywords": event.keywords,
        "data": event.data,
        "message": event.rendered_message,
        "warnings": list(event.parse_warnings),
    }


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "category": finding.category.value,
        "priority": finding.priority,
        "title": finding.title,
        "explanation": finding.explanation,
        "recommendation": finding.recommendation,
        "count": len(finding.events),
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "channel": finding.events[0].channel if finding.events else "",
        "provider": finding.events[0].provider if finding.events else "",
        "event_id": finding.events[0].event_id if finding.events else 0,
        "events": [_event_payload(event) for event in finding.events],
    }


def _node_payload(node: NodeResult) -> dict[str, Any]:
    return {
        "name": node.node,
        "status": node.status.value,
        "period_start": _iso(node.period_start),
        "period_end": _iso(node.period_end),
        "records_read": node.records_read,
        "logs_seen": list(node.logs_seen),
        "archives_seen": list(node.archives_seen),
        "counts": {
            "critical": node.critical_count,
            "error": node.error_count,
            "security": node.security_count,
            "occurrences": sum(
                len(finding.events) for finding in node.findings
            ),
        },
        "findings": [
            _finding_payload(finding) for finding in node.findings
        ],
        "diagnostics": [
            {
                "level": diagnostic.level.value,
                "source": diagnostic.source,
                "message": diagnostic.message,
            }
            for diagnostic in node.diagnostics
        ],
    }


def report_payload(run: AuditRun) -> dict[str, Any]:
    nodes = [_node_payload(node) for node in run.nodes]
    period_starts = [
        node.period_start for node in run.nodes if node.period_start is not None
    ]
    period_ends = [
        node.period_end for node in run.nodes if node.period_end is not None
    ]
    return {
        "title": "Сводный отчёт аудита событий Windows",
        "source_root": str(run.source_root),
        "created_at": _iso(run.created_at),
        "period_start": _iso(min(period_starts)) if period_starts else None,
        "period_end": _iso(max(period_ends)) if period_ends else None,
        "summary": {
            "nodes": len(nodes),
            "archives": int(run.metadata.get("archive_count", 0)),
            "evtx": int(run.metadata.get("evtx_count", 0)),
            "critical": sum(node["counts"]["critical"] for node in nodes),
            "error": sum(node["counts"]["error"] for node in nodes),
            "security": sum(node["counts"]["security"] for node in nodes),
            "occurrences": sum(
                node["counts"]["occurrences"] for node in nodes
            ),
            "partial": sum(
                node["status"] in {"partial", "failed"} for node in nodes
            ),
        },
        "nodes": nodes,
        "metadata": run.metadata,
    }


def safe_json(value: object) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render_report(run: AuditRun) -> str:
    template = (
        resources.files("evtx_auditor")
        .joinpath("report_template.html")
        .read_text(encoding="utf-8")
    )
    return template.replace("__REPORT_DATA__", safe_json(report_payload(run)))
