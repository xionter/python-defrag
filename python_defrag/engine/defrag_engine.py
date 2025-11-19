"""Core logic responsible for planning and executing defragmentation."""

from __future__ import annotations

import logging
import os
import shutil
import struct
from datetime import datetime
from typing import Dict, List, MutableMapping, Sequence, cast

from ..analysis.analyser import FAT32Analyzer
from ..parser.fat32_parser import FAT32Parser

MovePlan = Dict[str, object]
logger = logging.getLogger(__name__)


class DefragmentationEngine:
    """Coordinates the high-level workflow for optimizing a FAT32 image."""

    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.analyzer = FAT32Analyzer(parser)
        self.modified_clusters: set[int] = set()

    def plan_defragmentation(self, report: Dict) -> List[MovePlan]:
        """Return a list describing how fragmented files should be relocated."""
        files = [f for f in report["files"] if f["fragments"] > 1]
        free_extents = [extent.copy() for extent in report["free_extents"]]
        if not files or not free_extents:
            return []

        files.sort(key=lambda item: (item["fragments"], item["size_bytes"]), reverse=True)
        plans: List[MovePlan] = []

        for file_info in files:
            clusters_needed = len(file_info["clusters"])
            extent = self._find_extent(free_extents, clusters_needed)
            if not extent:
                continue

            plans.append(
                {
                    "file_path": file_info["path"],
                    "source_clusters": file_info["clusters"],
                    "target_start": extent["start_lcn"],
                    "size_bytes": file_info["size_bytes"],
                    "fragments_before": file_info["fragments"],
                    "fragments_after": 1,
                    "clusters_needed": clusters_needed,
                    "first_cluster": file_info["first_cluster"],
                }
            )
            extent["start_lcn"] += clusters_needed
            extent["length"] -= clusters_needed
            free_extents[:] = [e for e in free_extents if e["length"] > 0]

        return plans

    @staticmethod
    def _find_extent(extents: List[MutableMapping[str, int]], length: int):
        for extent in extents:
            if extent["length"] >= length:
                return extent
        return None

    def create_output_image(self, output_path: str | None) -> str:
        """Create a working copy of the disk image to modify."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not output_path:
            original_name = os.path.basename(self.parser.image_path)
            name, ext = os.path.splitext(original_name)
            output_path = f"images/{name}_defragmented_{timestamp}{ext}"

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        shutil.copy2(self.parser.image_path, output_path)
        return output_path

    def move_file_clusters(self, output_parser: FAT32Parser, move: MovePlan) -> bool:
        """Physically move cluster data described by ``move``."""
        try:
            source_clusters = cast(Sequence[int], move["source_clusters"])
            target_start = int(move["target_start"])
            file_size = int(move["size_bytes"])
            data = self._read_cluster_bytes(source_clusters, file_size)
            self._write_cluster_bytes(output_parser, target_start, source_clusters, data)
            self.update_fat_chain(output_parser, target_start, len(source_clusters))
            self.update_directory_entry(
                output_parser,
                old_first_cluster=int(move["first_cluster"]),
                new_first_cluster=target_start,
            )
            return True
        except Exception as exc:
            logger.exception("Failed to move clusters for %s", move.get("file_path"), exc_info=exc)
            return False

    def _read_cluster_bytes(self, clusters: Sequence[int], file_size: int) -> bytes:
        bytes_per_cluster = self.parser.boot_sector.cluster_size
        buffer = bytearray()
        for cluster in clusters:
            chunk = self.parser.read_cluster(cluster)
            if len(chunk) < bytes_per_cluster:
                chunk = chunk.ljust(bytes_per_cluster, b"\x00")
            else:
                chunk = chunk[:bytes_per_cluster]
            buffer.extend(chunk)
        return bytes(buffer[:file_size])

    def _write_cluster_bytes(
        self,
        output_parser: FAT32Parser,
        target_start: int,
        source_clusters: Sequence[int],
        data: bytes,
    ) -> None:
        bytes_per_cluster = output_parser.boot_sector.cluster_size
        total_clusters = len(source_clusters)
        for idx in range(total_clusters):
            start = idx * bytes_per_cluster
            if start >= len(data):
                break
            end = min(start + bytes_per_cluster, len(data))
            chunk = data[start:end].ljust(bytes_per_cluster, b"\x00")
            target_cluster = target_start + idx
            output_parser.write_cluster(target_cluster, chunk)
            self.modified_clusters.add(target_cluster)

    def update_fat_chain(self, output_parser: FAT32Parser, start_cluster: int, length: int) -> None:
        for offset in range(length):
            current = start_cluster + offset
            next_cluster = 0x0FFFFFFF if offset == length - 1 else current + 1
            output_parser.write_fat_entry(current, next_cluster)

    def update_directory_entry(
        self,
        output_parser: FAT32Parser,
        old_first_cluster: int,
        new_first_cluster: int,
    ) -> None:
        """Rewrite the directory entry for the moved file."""

        def _decode_name(entry_data: bytes) -> str:
            name = entry_data[0:8].decode("ascii", errors="replace").rstrip()
            ext = entry_data[8:11].decode("ascii", errors="replace").rstrip()
            if ext:
                return f"{name}.{ext}"
            return name

        def _walk_directory(cluster: int, path: str) -> bool:
            try:
                chain = (
                    output_parser.get_cluster_chain(cluster)
                    if cluster >= 2
                    else [cluster]
                )
                for chain_cluster in chain:
                    base_offset = output_parser.cluster_to_offset(chain_cluster)
                    raw = output_parser.read_cluster(chain_cluster)
                    offset = 0
                    while offset + 32 <= len(raw):
                        entry = raw[offset : offset + 32]
                        if entry[0] == 0x00:
                            break
                        if entry[0] == 0xE5 or entry[11] == 0x0F:
                            offset += 32
                            continue
                        entry_first = self._entry_first_cluster(entry)
                        if entry_first == old_first_cluster:
                            updated = self._patch_entry(entry, new_first_cluster)
                            handle = output_parser.file_handle
                            handle.seek(base_offset + offset)
                            handle.write(updated)
                            return True

                        attrs = entry[11]
                        is_dir = bool(attrs & 0x10)
                        is_volume = bool(attrs & 0x08)
                        name = _decode_name(entry)
                        if (
                            is_dir
                            and not is_volume
                            and entry_first >= 2
                            and name not in (".", "..")
                        ):
                            next_path = f"{path}/{name}".replace("//", "/")
                            if _walk_directory(entry_first, next_path):
                                return True
                        offset += 32
            except (OSError, ValueError, struct.error) as exc:
                logger.exception(
                    "Error while traversing directory cluster %s (%s)",
                    cluster,
                    path,
                    exc_info=exc,
                )
                return False
            return False

        root_cluster = output_parser.boot_sector.root_dir_cluster
        _walk_directory(root_cluster, "/")

    @staticmethod
    def _collect_directory_entries(raw: bytes) -> List[bytes]:
        entries: List[bytes] = []
        for pos in range(0, len(raw), 32):
            entry = raw[pos : pos + 32]
            if len(entry) < 32 or entry[0] == 0x00:
                break
            if entry[0] != 0xE5 and entry[11] != 0x0F:
                entries.append(entry)
        return entries

    @staticmethod
    def _entry_first_cluster(entry_data: bytes) -> int:
        high = struct.unpack("<H", entry_data[20:22])[0]
        low = struct.unpack("<H", entry_data[26:28])[0]
        return (high << 16) | low

    @staticmethod
    def _patch_entry(entry_data: bytes, new_first_cluster: int) -> bytes:
        new_high = (new_first_cluster >> 16) & 0xFFFF
        new_low = new_first_cluster & 0xFFFF
        updated = bytearray(entry_data)
        updated[20:22] = struct.pack("<H", new_high)
        updated[26:28] = struct.pack("<H", new_low)
        return bytes(updated)

    def execute_defragmentation(self, moves: List[MovePlan], output_path: str | None = None) -> Dict:
        """Execute planned moves and report success/failure statistics."""
        output_image_path = self.create_output_image(output_path)
        success = 0
        failed: List[str] = []
        self.modified_clusters.clear()

        try:
            with FAT32Parser(output_image_path, writable=True) as output_parser:
                output_parser.parse_boot_sector()
                for move in moves:
                    if self.move_file_clusters(output_parser, move):
                        self._clear_old_chain(output_parser, move["source_clusters"])
                        success += 1
                    else:
                        failed.append(str(move["file_path"]))
                output_parser.sync()
        except Exception as exc:
            total = len(moves)
            return {
                "output_image": output_image_path,
                "total_moves": total,
                "successful_moves": success,
                "success_rate": (success / total) * 100 if total else 0,
                "error": str(exc),
                "failed_moves": failed,
            }

        total = len(moves)
        return {
            "output_image": output_image_path,
            "total_moves": total,
            "successful_moves": success,
            "success_rate": (success / total) * 100 if total else 100,
            "failed_moves": failed,
        }

    def _clear_old_chain(self, output_parser: FAT32Parser, clusters: Sequence[int]) -> None:
        for cluster in clusters:
            if cluster not in self.modified_clusters:
                output_parser.write_fat_entry(cluster, 0)

    def defragment(self, output_path: str | None = None) -> Dict:
        """Analyze the current image, plan moves, and optionally execute them."""
        report = self.analyzer.analyze()
        moves = self.plan_defragmentation(report)
        if not moves:
            return {
                "original_report": report,
                "planned_moves": [],
                "executed": False,
                "message": "No fragmented files found",
            }

        execution = self.execute_defragmentation(moves, output_path)
        return {
            "original_report": report,
            "planned_moves": moves,
            "execution_result": execution,
            "executed": True,
        }
