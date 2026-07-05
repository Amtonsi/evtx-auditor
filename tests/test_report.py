from evtx_auditor.report import render_report, report_payload


def test_report_is_offline_and_contains_each_node(sample_audit_run):
    html = render_report(sample_audit_run)

    assert "40010-SRV-04B" in html
    assert "NEW-OPER-4" in html
    assert "https://" not in html
    assert "http://" not in html
    assert 'id="report-data"' in html
    assert "Приоритет проверки узлов" in html
    assert "Диагностика обработки" in html
    assert "fetch(" not in html
    assert "Групповой образец" in html
    assert "Разработал: Абдрахманов Амаль Даулетович" in html
    assert "Формат" in html


def test_report_escapes_event_content(sample_audit_run_with_script_text):
    html = render_report(sample_audit_run_with_script_text)

    assert "</script><script>alert(1)</script>" not in html
    assert "\\u003c/script\\u003e" in html


def test_report_payload_marks_event_source_format(sample_audit_run):
    payload = report_payload(sample_audit_run)
    event = payload["nodes"][0]["findings"][0]["events"][0]

    assert event["source_format"] == "EVTX"
