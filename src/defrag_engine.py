from typing import List, Dict
import os
import shutil
import struct
from datetime import datetime
from .fat32_parser import FAT32Parser
from .analyser import FAT32Analyzer


class DefragmentationEngine:
    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.analyzer = FAT32Analyzer(parser)
        self.modified_clusters = set()
        self.root_dir_entry_cache: Dict[int, int] = {}


    def plan_defragmentation(self, report: Dict) -> List[Dict]:
        moves: List[Dict] = []
        files = report["files"]
        free_extents = report["free_extents"]

        fragmented_files = [f for f in files if f["fragments"] > 1]
        if not free_extents or not fragmented_files:
            return moves

        fragmented_files.sort(
            key=lambda x: (x["fragments"], x["size_bytes"]),
            reverse=True,
        )

        free_extents_working = [e.copy() for e in free_extents]

        for file_info in fragmented_files:
            clusters_needed = len(file_info["clusters"])
            best_idx = None
            best_len = None

            for idx, extent in enumerate(free_extents_working):
                length = extent["length"]
                if length >= clusters_needed:
                    if best_len is None or length < best_len:
                        best_len = length
                        best_idx = idx

            if best_idx is None:
                continue

            extent = free_extents_working[best_idx]
            target_start = extent["start_lcn"]

            moves.append({
                "file_path": file_info["path"],
                "source_clusters": file_info["clusters"],
                "target_start": target_start,
                "size_bytes": file_info["size_bytes"],
                "fragments_before": file_info["fragments"],
                "fragments_after": 1,
                "clusters_needed": clusters_needed,
                "first_cluster": file_info["first_cluster"],
            })

            extent["start_lcn"] += clusters_needed
            extent["length"] -= clusters_needed

            free_extents_working = [e for e in free_extents_working if e["length"] > 0]

        return moves

    def create_output_image(self, output_path: str | None) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not output_path:
            original_name = os.path.basename(self.parser.image_path)
            name, ext = os.path.splitext(original_name)
            output_path = f"images/{name}_defragmented_{timestamp}{ext}"

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        shutil.copy2(self.parser.image_path, output_path)
        return output_path

    def build_root_dir_cache(self, output_parser: FAT32Parser) -> None:
        self.root_dir_entry_cache.clear()

        root_cluster = output_parser.boot_sector.root_dir_cluster
        root_data = output_parser.read_cluster(root_cluster)

        pos = 0
        base_offset = output_parser.cluster_to_offset(root_cluster)

        while pos + 32 <= len(root_data):
            entry = root_data[pos:pos + 32]

            if entry[0] == 0x00:
                break

            if entry[0] == 0xE5 or entry[11] == 0x0F:
                pos += 32
                continue

            high = struct.unpack("<H", entry[20:22])[0]
            low = struct.unpack("<H", entry[26:28])[0]
            first_cluster = (high << 16) | low

            entry_offset = base_offset + pos
            self.root_dir_entry_cache[first_cluster] = entry_offset

            pos += 32


    def move_file_clusters(self, output_parser: FAT32Parser, move: Dict) -> bool:
        try:
            source_clusters: List[int] = move["source_clusters"]
            target_start: int = move["target_start"]
            file_size: int = move["size_bytes"]

            bytes_per_cluster = (
                self.parser.boot_sector.sectors_per_cluster
                * self.parser.boot_sector.bytes_per_sector
            )

            remaining = file_size

            for src_cluster, dst_cluster in zip(
                source_clusters,
                range(target_start, target_start + len(source_clusters))
            ):
                if remaining <= 0:
                    break

                data = self.parser.read_cluster(src_cluster)

                if len(data) < bytes_per_cluster:
                    data = data + b"\x00" * (bytes_per_cluster - len(data))
                elif len(data) > bytes_per_cluster:
                    data = data[:bytes_per_cluster]

                if remaining < bytes_per_cluster:
                    data = data[:remaining] + b"\x00" * (bytes_per_cluster - remaining)

                output_parser.write_cluster(dst_cluster, data)
                self.modified_clusters.add(dst_cluster)
                remaining -= bytes_per_cluster

            self.update_fat_chain(output_parser, target_start, len(source_clusters))

            self.update_directory_entry(
                output_parser,
                move["first_cluster"],
                target_start,
                move["file_path"],
            )

            return True

        except Exception:
            return False

    def update_fat_chain(self, output_parser: FAT32Parser, start_cluster: int, length: int):
        for i in range(length):
            current = start_cluster + i
            next_c = 0x0FFFFFFF if i == length - 1 else start_cluster + i + 1
            output_parser.write_fat_entry(current, next_c)


    def update_directory_entry(
        self,
        output_parser: FAT32Parser,
        old_first_cluster: int,
        new_first_cluster: int,
        file_path: str,
    ):
        try:
            offset = self.root_dir_entry_cache.get(old_first_cluster)
            if offset is not None:
                output_parser.file_handle.seek(offset)
                entry_data = output_parser.file_handle.read(32)
                if len(entry_data) == 32:
                    new_high = (new_first_cluster >> 16) & 0xFFFF
                    new_low = new_first_cluster & 0xFFFF

                    updated = bytearray(entry_data)
                    updated[20:22] = struct.pack("<H", new_high)
                    updated[26:28] = struct.pack("<H", new_low)

                    output_parser.file_handle.seek(offset)
                    output_parser.file_handle.write(updated)

                    del self.root_dir_entry_cache[old_first_cluster]
                    self.root_dir_entry_cache[new_first_cluster] = offset
                    return

            root_cluster = output_parser.boot_sector.root_dir_cluster
            root_data = output_parser.read_cluster(root_cluster)

            entries: List[bytes] = []
            pos = 0
            while pos + 32 <= len(root_data):
                entry = root_data[pos:pos + 32]
                if entry[0] == 0x00:
                    break
                if entry[0] != 0xE5 and entry[11] != 0x0F:
                    entries.append((entry, pos))
                pos += 32

            for entry_data, entry_pos in entries:
                if len(entry_data) < 32:
                    continue
                high = struct.unpack("<H", entry_data[20:22])[0]
                low = struct.unpack("<H", entry_data[26:28])[0]
                entry_first = (high << 16) | low

                if entry_first == old_first_cluster:
                    new_high = (new_first_cluster >> 16) & 0xFFFF
                    new_low = new_first_cluster & 0xFFFF

                    updated = bytearray(entry_data)
                    updated[20:22] = struct.pack("<H", new_high)
                    updated[26:28] = struct.pack("<H", new_low)

                    entry_offset = output_parser.cluster_to_offset(root_cluster) + entry_pos
                    output_parser.file_handle.seek(entry_offset)
                    output_parser.file_handle.write(updated)

                    self.root_dir_entry_cache[new_first_cluster] = entry_offset
                    if old_first_cluster in self.root_dir_entry_cache:
                        del self.root_dir_entry_cache[old_first_cluster]
                    return
        except Exception:
            pass

    def execute_defragmentation(self, moves: List[Dict], output_path: str | None = None) -> Dict:
        output_image_path = self.create_output_image(output_path)
        success = 0
        total = len(moves)
        failed: List[str] = []

        try:
            with FAT32Parser(output_image_path, writable=True) as output_parser:
                output_parser.parse_boot_sector()
                output_parser.read_cluster(2)

                self.build_root_dir_cache(output_parser)

                for move in moves:
                    if self.move_file_clusters(output_parser, move):
                        for cluster in move["source_clusters"]:
                            if cluster not in self.modified_clusters:
                                output_parser.write_fat_entry(cluster, 0)
                        success += 1
                    else:
                        failed.append(move["file_path"])

                output_parser.sync()
        except Exception as e:
            return {
                "output_image": output_image_path,
                "total_moves": total,
                "successful_moves": success,
                "success_rate": (success / total) * 100 if total > 0 else 0,
                "error": str(e),
                "failed_moves": failed,
            }

        return {
            "output_image": output_image_path,
            "total_moves": total,
            "successful_moves": success,
            "success_rate": (success / total) * 100 if total > 0 else 100,
            "failed_moves": failed,
        }

    def analyze_fragmentation(self) -> Dict:
        return self.analyzer.analyze()

    def defragment(
        self,
        output_path: str | None = None,
        dry_run: bool = True,
        verify: bool = True,
    ) -> Dict:
        report = self.analyzer.analyze()
        moves = self.plan_defragmentation(report)

        if not moves:
            result = {
                "original_report": report,
                "planned_moves": [],
                "executed": False,
                "message": "No fragmented files found",
            }
            if dry_run:
                result["simulation_results"] = {
                    "files_optimized": 0,
                    "total_clusters_moved": 0,
                    "fragmentation_reduction": 0,
                    "total_moves": 0,
                    "estimated_time_seconds": 0.0,
                }
            return result

        if dry_run:
            total_clusters = sum(m["clusters_needed"] for m in moves)
            simulation = {
                "files_optimized": len(moves),
                "total_clusters_moved": total_clusters,
                "fragmentation_reduction": sum(
                    m["fragments_before"] - m["fragments_after"] for m in moves
                ),
                "total_moves": len(moves),
                "estimated_time_seconds": total_clusters * 0.001,
            }
            return {
                "original_report": report,
                "planned_moves": moves,
                "simulation_results": simulation,
                "executed": False,
            }

        exec_result = self.execute_defragmentation(moves, output_path)

        result: Dict = {
            "original_report": report,
            "planned_moves": moves,
            "execution_result": exec_result,
            "executed": True,
        }

        exec_result = self.execute_defragmentation(moves, output_path)

        result: Dict = {
            "original_report": report,
            "planned_moves": moves,
            "execution_result": exec_result,
            "executed": True,
        }

        if verify and exec_result.get("output_image"):
            try:
                new_image_path = exec_result["output_image"]
                with FAT32Parser(new_image_path, writable=False) as verify_parser:
                    verify_parser.parse_boot_sector()
                    verify_analyzer = FAT32Analyzer(verify_parser)
                    new_report = verify_analyzer.analyze()

                verify_result = self._verify_reports(report, new_report)
                verify_result["new_report"] = new_report

                result["verify"] = verify_result

            except Exception as e:
                result["verify"] = {
                    "ok": False,
                    "error": str(e),
                }

        return result

    def _verify_reports(self, original_report: Dict, new_report: Dict) -> Dict:
        orig_stats = original_report["stats"]
        new_stats = new_report["stats"]

        orig_files = {f["path"]: f for f in original_report["files"]}
        new_files = {f["path"]: f for f in new_report["files"]}

        checks: Dict[str, bool] = {}

        checks["same_file_paths"] = (set(orig_files.keys()) == set(new_files.keys()))

        checks["same_files_total"] = (
            orig_stats["files_total"] == new_stats["files_total"]
        )

        checks["same_total_size_bytes"] = (
            orig_stats["total_size_bytes"] == new_stats["total_size_bytes"]
        )

        per_file_sizes_ok = True
        common_paths = set(orig_files.keys()) & set(new_files.keys())
        for path in common_paths:
            if orig_files[path]["size_bytes"] != new_files[path]["size_bytes"]:
                per_file_sizes_ok = False
                break
        checks["same_each_file_size"] = per_file_sizes_ok

        checks["fragmentation_not_worse"] = (
            new_stats["volume_fragmentation_index"]
            <= orig_stats["volume_fragmentation_index"] + 1e-9
        )

        ok = all(checks.values())

        return {
            "ok": ok,
            "checks": checks,
            "original_stats": orig_stats,
            "new_stats": new_stats,
        }
