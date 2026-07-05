from pathlib import Path, PurePosixPath
from shutil import copyfileobj
from zipfile import ZipFile, ZipInfo

MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_ARCHIVE_SIZE = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 1000
SUPPORTED_LOG_SUFFIXES = (".evtx", ".evt")


class UnsafeArchiveError(ValueError):
    pass


class ArchiveLimitError(ValueError):
    pass


def _validated_relative_path(info: ZipInfo) -> Path:
    value = PurePosixPath(info.filename.replace("\\", "/"))
    if (
        value.is_absolute()
        or ".." in value.parts
        or not value.parts
        or ":" in value.parts[0]
    ):
        raise UnsafeArchiveError(info.filename)
    return Path(*value.parts)


def extract_event_logs(archive_path: Path, destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    extracted: list[Path] = []
    with ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ArchiveLimitError(
                f"Слишком много записей ZIP: {len(entries)}"
            )
        selected = [
            info
            for info in entries
            if not info.is_dir()
            and info.filename.lower().endswith(SUPPORTED_LOG_SUFFIXES)
        ]
        total_size = sum(info.file_size for info in selected)
        if total_size > MAX_ARCHIVE_SIZE:
            raise ArchiveLimitError(
                f"Распакованный объём превышает {MAX_ARCHIVE_SIZE}"
            )
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
    return sorted(extracted, key=lambda item: str(item).casefold())


def extract_evtx(archive_path: Path, destination: Path) -> list[Path]:
    return extract_event_logs(archive_path, destination)
