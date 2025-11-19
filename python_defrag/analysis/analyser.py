"""High-level FAT32 volume inspection and reporting utilities."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Tuple

from ..parser.directory_entry import DirectoryEntry, DirectoryParser
from ..parser.fat32_parser import FAT32Parser

Extent = Tuple[int, int]


@dataclass(slots=True)
class FileRecord:
    """Represents either a file or directory discovered while walking the volume."""

    path: str
    size_bytes: int
    first_cluster: int
    clusters: List[int]
    extents: List[Extent]
    fragments: int
    is_directory: bool


def _to_extents(chain: List[int]) -> List[Extent]:
    """Convert a cluster chain into (start, length) extents."""
    if not chain:
        return []

    extents: List[Extent] = []
    start = chain[0]
    length = 1
    for previous, current in zip(chain, chain[1:]):
        if current == previous + 1:
            length += 1
        else:
            extents.append((start, length))
            start, length = current, 1
    extents.append((start, length))
    return extents


class FAT32Analyzer:
    """Gathers fragmentation statistics and directory metadata."""

    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.dir_parser = DirectoryParser(self.parser)
        self._cluster_chain_cache: Dict[int, List[int]] = {}
        self._dir_bytes_cache: Dict[int, bytes] = {}

    # ------------------------------------------------------------------ helpers --
    def cluster_size(self) -> int:
        boot = self.parser.boot_sector
        return boot.cluster_size

    def total_clusters(self) -> int:
        boot = self.parser.boot_sector
        data_sectors = boot.total_sectors - (
            boot.reserved_sectors + boot.num_fats * boot.sectors_per_fat
        )
        return data_sectors // boot.sectors_per_cluster

    def _cluster_chain(self, start_cluster: int) -> List[int]:
        if start_cluster in self._cluster_chain_cache:
            return self._cluster_chain_cache[start_cluster]
        chain = self.parser.get_cluster_chain(start_cluster)
        self._cluster_chain_cache[start_cluster] = chain
        return chain

    def _chain_bytes(self, start_cluster: int) -> bytes:
        if start_cluster in self._dir_bytes_cache:
            return self._dir_bytes_cache[start_cluster]
        out = bytearray()
        for cluster in self._cluster_chain(start_cluster):
            out.extend(self.parser.read_cluster(cluster))
        data = bytes(out)
        self._dir_bytes_cache[start_cluster] = data
        return data

    def _parse_directory(self, cluster: int) -> List[DirectoryEntry]:
        raw = self._chain_bytes(cluster)
        return self.dir_parser.parse_directory_entries(raw)

    # ---------------------------------------------------------------- directory --
    def walk(self) -> List[FileRecord]:
        """Traverse the directory tree and return collected file records."""
        root_cluster = self.parser.boot_sector.root_dir_cluster
        records: List[FileRecord] = []
        self._walk_dir(cluster=root_cluster, prefix="/", out=records)
        return records

    def _walk_dir(self, cluster: int, prefix: str, out: List[FileRecord]) -> None:
        entries = self._parse_directory(cluster)
        out.append(self._record_for_dir(prefix.rstrip("/"), cluster))
        for entry in entries:
            name = entry.name.strip()
            if entry.is_volume_label or not name or name in (".", ".."):
                continue
            path = prefix + (entry.full_name.strip() or name)
            chain = self._cluster_chain(entry.first_cluster) if entry.first_cluster >= 2 else []
            extents = _to_extents(chain)
            out.append(
                FileRecord(
                    path=path,
                    size_bytes=entry.file_size,
                    first_cluster=entry.first_cluster,
                    clusters=chain,
                    extents=extents,
                    fragments=len(extents),
                    is_directory=entry.is_directory,
                )
            )
            if entry.is_directory and entry.first_cluster >= 2:
                self._walk_dir(entry.first_cluster, path.rstrip("/") + "/", out)

    def _record_for_dir(self, path: str, first_cluster: int) -> FileRecord:
        chain = self._cluster_chain(first_cluster) if first_cluster >= 2 else []
        extents = _to_extents(chain)
        return FileRecord(
            path=path or "/",
            size_bytes=0,
            first_cluster=first_cluster,
            clusters=chain,
            extents=extents,
            fragments=len(extents),
            is_directory=True,
        )

    # ----------------------------------------------------------- bitmap helpers --
    def build_allocation_bitmap(self, records: Iterable[FileRecord]) -> List[int]:
        bitmap = [0] * self.total_clusters()
        for rec in records:
            for cluster in rec.clusters:
                idx = cluster - 2
                if 0 <= idx < len(bitmap):
                    bitmap[idx] = 1
        return bitmap

    @staticmethod
    def free_extents(bitmap: List[int]) -> List[Extent]:
        extents: List[Extent] = []
        size = len(bitmap)
        idx = 0
        while idx < size:
            if bitmap[idx] == 0:
                start = idx
                while idx < size and bitmap[idx] == 0:
                    idx += 1
                extents.append((start + 2, idx - start))
            else:
                idx += 1
        return extents

    # -------------------------------------------------------------- stats/report --
    def stats(self, records: List[FileRecord], free_runs: List[Extent]) -> Dict:
        files = [r for r in records if not r.is_directory]
        fragmented_files = [r for r in files if r.fragments > 1]
        total_fragments = sum(r.fragments for r in files)

        largest_free = max((length for _, length in free_runs), default=0)
        fragmentation_index = (
            sum(r.fragments - 1 for r in files) / max(1, total_fragments)
        )

        return {
            "files_total": len(files),
            "files_fragmented": len(fragmented_files),
            "files_fragmented_pct": (len(fragmented_files) * 100.0 / len(files))
            if files
            else 0.0,
            "avg_fragments_per_file": (total_fragments / len(files)) if files else 0.0,
            "max_fragments": max((r.fragments for r in files), default=0),
            "total_size_bytes": sum(r.size_bytes for r in files),
            "cluster_size_bytes": self.cluster_size(),
            "total_clusters": self.total_clusters(),
            "free_runs_count": len(free_runs),
            "largest_free_run_clusters": largest_free,
            "largest_free_run_bytes": largest_free * self.cluster_size(),
            "volume_fragmentation_index": fragmentation_index,
        }

    def analyze(self) -> Dict:
        """Return a comprehensive fragmentation report."""
        if not self.parser.boot_sector:
            self.parser.parse_boot_sector()
        records = self.walk()
        bitmap = self.build_allocation_bitmap(records)
        free_runs = self.free_extents(bitmap)
        return {
            "stats": self.stats(records, free_runs),
            "files": [asdict(r) for r in records if not r.is_directory],
            "dirs": [asdict(r) for r in records if r.is_directory],
            "free_extents": [{"start_lcn": start, "length": length} for start, length in free_runs],
        }


def print_summary(report: Dict) -> None:
    """Pretty-print a human readable summary suitable for CLI use."""
    stats = report["stats"]
    print(f"Cluster size: {stats['cluster_size_bytes']} bytes")
    print(
        "Files: {total} | Fragmented: {frag} ({pct:.1f}%) | "
        "Avg frags/file: {avg:.2f} | Max: {max_frag}".format(
            total=stats["files_total"],
            frag=stats["files_fragmented"],
            pct=stats["files_fragmented_pct"],
            avg=stats["avg_fragments_per_file"],
            max_frag=stats["max_fragments"],
        )
    )
    print(
        "Free runs: {count} | Largest free: {clusters} clusters "
        "({bytes_kib} KiB)".format(
            count=stats["free_runs_count"],
            clusters=stats["largest_free_run_clusters"],
            bytes_kib=stats["largest_free_run_bytes"] // 1024,
        )
    )
    print(f"Volume fragmentation index: {stats['volume_fragmentation_index']:.3f}")
