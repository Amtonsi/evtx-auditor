from __future__ import annotations

import hashlib
import re
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def inventory_archives(root: Path) -> dict[str, object]:
    archives = sorted(
        root.rglob("*.zip"), key=lambda item: str(item).casefold()
    )
    evtx_count = 0
    hashes: dict[str, str] = {}
    for archive_path in archives:
        hashes[str(archive_path)] = sha256_file(archive_path)
        with ZipFile(archive_path) as archive:
            evtx_count += sum(
                not info.is_dir()
                and info.filename.casefold().endswith(".evtx")
                for info in archive.infolist()
            )
    return {
        "archive_count": len(archives),
        "evtx_count": evtx_count,
        "hashes": hashes,
    }


def is_offline_html(html: str) -> bool:
    return re.search(r"https?://", html, flags=re.IGNORECASE) is None


def create_source_zip(
    root: Path, destination: Path, files: list[str]
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
        for relative_text in sorted(files, key=str.casefold):
            relative = Path(relative_text)
            source = (root / relative).resolve()
            if not source.is_file() or not source.is_relative_to(root.resolve()):
                raise ValueError(f"Недопустимый файл исходников: {relative}")
            archive.write(source, relative.as_posix())

