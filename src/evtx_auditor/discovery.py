from collections import defaultdict
from pathlib import Path

from .models import ArchiveSource


def discover_archives(root: Path) -> list[ArchiveSource]:
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    return [
        ArchiveSource(path=path, node_hint=path.parent.name)
        for path in sorted(
            root.rglob("*.zip"), key=lambda item: str(item).casefold()
        )
    ]


def group_archives_by_node(
    sources: list[ArchiveSource],
) -> dict[str, list[ArchiveSource]]:
    grouped: dict[str, list[ArchiveSource]] = defaultdict(list)
    for source in sources:
        grouped[source.node_hint].append(source)
    return dict(sorted(grouped.items(), key=lambda item: item[0].casefold()))

