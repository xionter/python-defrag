from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Optional
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parser')))
from fat32_parser import FAT32Parser
from directory_entry import DirectoryParser

from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional

@dataclass
class FileRecord:
    path: str
    size_bytes: int
    first_cluster: int
    clusters: List[int]
    extents: List[Tuple[int, int]]
    fragments: int
    is_directory: bool


def to_extents(chain: List[int]) -> List[Tuple[int, int]]:
    if not chain:
        return []
    extents: List[Tuple[int,int]] = []
    start = chain[0]
    length = 1
    for prev, cur in zip(chain, chain[1:]):
        if cur == prev + 1:
            length += 1
        else:
            extents.append((start, length))
            start, length = cur, 1
    extents.append((start, length))
    return extents

class FAT32Analyzer:
    def __init__(self, parser: FAT32Parser):
        self.p = parser
        self.dir_parser = DirectoryParser(self.p)
        self._cluster_chain_cache: Dict[int, List[int]] = {}
        self._dir_bytes_cache: Dict[int, bytes] = {}

    def cluster_size(self) -> int:
        bs = self.p.boot_sector
        return bs.sectors_per_cluster * bs.bytes_per_sector

    def total_clusters(self) -> int:
        bs = self.p.boot_sector
        data_sectors = bs.total_sectors - (bs.reserved_sectors + bs.num_fats * bs.sectors_per_fat)
        return data_sectors // bs.sectors_per_cluster

    def get_chain(self, start_cluster: int) -> List[int]:
        if start_cluster in self._cluster_chain_cache:
            return self._cluster_chain_cache[start_cluster]
        chain = self.p.get_cluster_chain(start_cluster)
        self._cluster_chain_cache[start_cluster] = chain
        return chain

    def read_chain_bytes(self, start_cluster: int) -> bytes:
        if start_cluster in self._dir_bytes_cache:
            return self._dir_bytes_cache[start_cluster]
        out = bytearray()
        for c in self.get_chain(start_cluster):
            out.extend(self.p.read_cluster(c))
        data = bytes(out)
        self._dir_bytes_cache[start_cluster] = data
        return data

    def parse_directory_by_cluster(self, cluster: int) -> List:
        raw = self.read_chain_bytes(cluster)
        return self.dir_parser.parse_directory_entries(raw)

    def walk(self) -> List[FileRecord]:
        bs = self.p.boot_sector
        root = bs.root_dir_cluster
        records: List[FileRecord] = []
        self._walk_dir(cluster=root, prefix="/", out=records)
        return records

    def _walk_dir(self, cluster: int, prefix: str, out: List[FileRecord]) -> None:
        entries = self.parse_directory_by_cluster(cluster)
        out.append(self._record_for_dir(prefix.rstrip("/"), cluster))
        for e in entries:
            if e.is_volume_label or not e.name.strip():
                continue
            nm = e.name.strip()
            if nm in (".", ".."):
                continue
            path = prefix + (e.full_name.strip() or nm)
            chain = self.get_chain(e.first_cluster) if e.first_cluster >= 2 else []
            exts = to_extents(chain)
            rec = FileRecord(
                path=path,
                size_bytes=e.file_size,
                first_cluster=e.first_cluster,
                clusters=chain,
                extents=exts,
                fragments=len(exts),
                is_directory=e.is_directory
            )
            out.append(rec)
            if e.is_directory and e.first_cluster >= 2:
                self._walk_dir(e.first_cluster, path.rstrip("/") + "/", out)

    def _record_for_dir(self, path: str, first_cluster: int) -> FileRecord:
        chain = self.get_chain(first_cluster) if first_cluster >= 2 else []
        exts = to_extents(chain)
        return FileRecord(
            path=path or "/",
            size_bytes=0,
            first_cluster=first_cluster,
            clusters=chain,
            extents=exts,
            fragments=len(exts),
            is_directory=True
        )

    def build_allocation_bitmap(self, records: List[FileRecord]) -> List[int]:
        n = self.total_clusters()
        bitmap = [0] * n
        for rec in records:
            for c in rec.clusters:
                idx = c - 2
                if 0 <= idx < n:
                    bitmap[idx] = 1
        return bitmap

    def free_extents(self, bitmap: List[int]) -> List[Tuple[int, int]]:
        out: List[Tuple[int,int]] = []
        i, n = 0, len(bitmap)
        while i < n:
            if bitmap[i] == 0:
                j = i
                while j < n and bitmap[j] == 0:
                    j += 1
                out.append((i + 2, j - i))
                i = j
            else:
                i += 1
        return out

    def stats(self, records: List[FileRecord], free_runs: List[Tuple[int,int]]) -> Dict:
        files = [r for r in records if not r.is_directory]
        fragmented = sum(1 for r in files if r.fragments > 1)
        avg_frags = (sum(r.fragments for r in files) / len(files)) if files else 0.0
        max_frags = max((r.fragments for r in files), default=0)
        total_size = sum(r.size_bytes for r in files)
        largest_free = max((ln for _, ln in free_runs), default=0)
        volume_frag_index = (sum(r.fragments - 1 for r in files) /
                             max(1, sum(r.fragments for r in files)))
        return {
            "files_total": len(files),
            "files_fragmented": fragmented,
            "files_fragmented_pct": (fragmented * 100.0 / len(files)) if files else 0.0,
            "avg_fragments_per_file": avg_frags,
            "max_fragments": max_frags,
            "total_size_bytes": total_size,
            "cluster_size_bytes": self.cluster_size(),
            "total_clusters": self.total_clusters(),
            "free_runs_count": len(free_runs),
            "largest_free_run_clusters": largest_free,
            "largest_free_run_bytes": largest_free * self.cluster_size(),
            "volume_fragmentation_index": volume_frag_index,
        }

    def analyze(self) -> Dict:
        if not self.p.boot_sector:
            self.p.parse_boot_sector()
        records = self.walk()
        bitmap = self.build_allocation_bitmap(records)
        free_runs = self.free_extents(bitmap)
        return {
            "stats": self.stats(records, free_runs),
            "files": [asdict(r) for r in records if not r.is_directory],
            "dirs": [asdict(r) for r in records if r.is_directory],
            "free_extents": [{"start_lcn": s, "length": l} for s, l in free_runs]
        }

def print_summary(report: Dict) -> None:
    s = report["stats"]
    print(f"Cluster size: {s['cluster_size_bytes']} bytes")
    print(f"Files: {s['files_total']} | Fragmented: {s['files_fragmented']} "
          f"({s['files_fragmented_pct']:.1f}%) | Avg frags/file: {s['avg_fragments_per_file']:.2f} | Max: {s['max_fragments']}")
    print(f"Free runs: {s['free_runs_count']} | Largest free: {s['largest_free_run_clusters']} clusters "
          f"({s['largest_free_run_bytes'] // 1024} KiB)")
    print(f"Volume fragmentation index: {s['volume_fragmentation_index']:.3f}")

