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

