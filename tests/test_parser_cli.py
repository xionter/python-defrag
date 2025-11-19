#!/usr/bin/env python3

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

from python_defrag.parser.directory_entry import DirectoryParser
from python_defrag.parser.fat32_parser import FAT32Parser


def main() -> None:
    default_image = PROJECT_ROOT / "images" / "FAT_32_32MB"
    image_path = os.environ.get("PYTHON_DEFRAG_IMAGE", str(default_image))

    try:
        with FAT32Parser(image_path) as fat_parser:
            boot_sector = fat_parser.parse_boot_sector()
            print("Boot Sector Information:")
            print(f"  Bytes per sector: {boot_sector.bytes_per_sector}")
            print(f"  Sectors per cluster: {boot_sector.sectors_per_cluster}")
            print(f"  Root directory cluster: {boot_sector.root_dir_cluster}")

            dir_parser = DirectoryParser(fat_parser)
            entries = dir_parser.parse_root_directory()

            print("\nRoot Directory Entries:")
            for entry in entries:
                type_str = "DIR" if entry.is_directory else "FILE"
                size_str = f"{entry.file_size:8d}" if not entry.is_directory else "       -"
                print(
                    f"  {entry.full_name:12s} {type_str} "
                    f"Cluster: {entry.first_cluster:6d} Size: {size_str}"
                )

    except Exception as exc:  # pragma: no cover - helper script
        print(f"Error: {exc}")


if __name__ == "__main__":
    main()
