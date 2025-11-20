from typing import List, Dict
import os
import shutil
import struct
from datetime import datetime
from fat32_parser import FAT32Parser
from analyser import FAT32Analyzer


class DefragmentationEngine:
    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.analyzer = FAT32Analyzer(parser)
        self.modified_clusters = set()

    def plan_defragmentation(self, report: Dict) -> List[Dict]:
        moves: List[Dict] = []
        files = report["files"]
        free_extents = report["free_extents"]

        fragmented_files = [f for f in files if f["fragments"] > 1]
        if not free_extents or not fragmented_files:
            return moves

        fragmented_files.sort(key=lambda x: (x["fragments"], x["size_bytes"]), reverse=True)
        free_extents_working = [e.copy() for e in free_extents]

        for file_info in fragmented_files:
            clusters_needed = len(file_info["clusters"])
            suitable_extent = None

            for extent in free_extents_working:
                if extent["length"] >= clusters_needed:
                    suitable_extent = extent
                    break

            if suitable_extent is None:
                continue

            moves.append({
                "file_path": file_info["path"],
                "source_clusters": file_info["clusters"],
                "target_start": suitable_extent["start_lcn"],
                "size_bytes": file_info["size_bytes"],
                "fragments_before": file_info["fragments"],
                "fragments_after": 1,
                "clusters_needed": clusters_needed,
                "first_cluster": file_info["first_cluster"],
            })

            suitable_extent["start_lcn"] += clusters_needed
            suitable_extent["length"] -= clusters_needed
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

    def move_file_clusters(self, output_parser: FAT32Parser, move: Dict) -> bool:
        try:
            source_clusters: List[int] = move["source_clusters"]
            target_start: int = move["target_start"]
            file_size: int = move["size_bytes"]

            bytes_per_cluster = (
                self.parser.boot_sector.sectors_per_cluster
                * self.parser.boot_sector.bytes_per_sector
            )

            file_data = bytearray()
            for cluster in source_clusters:
                data = self.parser.read_cluster(cluster)
                if len(data) == 0:
                    data = b"\x00" * bytes_per_cluster
                elif len(data) != bytes_per_cluster:
                    if len(data) < bytes_per_cluster:
                        data += b"\x00" * (bytes_per_cluster - len(data))
                    else:
                        data = data[:bytes_per_cluster]
                file_data.extend(data)

            if len(file_data) > file_size:
                file_data = file_data[:file_size]

            for i, target_cluster in enumerate(
                range(target_start, target_start + len(source_clusters))
            ):
                start = i * bytes_per_cluster
                end = min(start + bytes_per_cluster, len(file_data))
                if start >= len(file_data):
                    break

                chunk = file_data[start:end]
                if len(chunk) < bytes_per_cluster:
                    chunk += b"\x00" * (bytes_per_cluster - len(chunk))

                output_parser.write_cluster(target_cluster, chunk)
                self.modified_clusters.add(target_cluster)

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
            root_cluster = output_parser.boot_sector.root_dir_cluster
            root_data = output_parser.read_cluster(root_cluster)

            entries: List[bytes] = []
            pos = 0
            while pos + 32 <= len(root_data):
                entry = root_data[pos : pos + 32]
                if entry[0] == 0x00:
                    break
                if entry[0] != 0xE5 and entry[11] != 0x0F:
                    entries.append(entry)
                pos += 32

            for i, entry_data in enumerate(entries):
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

                    entry_offset = i * 32
                    offset = output_parser.cluster_to_offset(root_cluster) + entry_offset
                    output_parser.file_handle.seek(offset)
                    output_parser.file_handle.write(updated)
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
                output_parser.read_cluster(2)  # простая проверка чтения

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

    def defragment(self, output_path: str | None = None) -> Dict:
        report = self.analyzer.analyze()
        moves = self.plan_defragmentation(report)

        if not moves:
            return {
                "original_report": report,
                "planned_moves": [],
                "executed": False,
                "message": "No fragmented files found",
            }

        exec_result = self.execute_defragmentation(moves, output_path)
        return {
            "original_report": report,
            "planned_moves": moves,
            "execution_result": exec_result,
            "executed": True,
        }
