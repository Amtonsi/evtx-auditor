from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_packaging_files_define_verified_windowed_build():
    spec = (ROOT / "EVTXAuditor.spec").read_text(encoding="utf-8")
    build = (ROOT / "scripts" / "build.ps1").read_text(encoding="utf-8")

    assert "report_template.html" in spec
    assert 'name="EVTXAuditor"' in spec
    assert "console=False" in spec
    assert "python -m pytest" not in build
    assert "-m pytest" in build
    assert "--basetemp" in build
    assert "$env:TEMP" in build
    assert "$env:TMP" in build
    assert "--self-test" in build


def test_readme_documents_offline_operation():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "30 дней" in readme
    assert "4625" in readme
    assert "не выполняет сетевых запросов" in readme
