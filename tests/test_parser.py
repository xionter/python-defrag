#!/usr/bin/env python3
import sys

from src import FAT32Parser, DirectoryParser


def main(image_path):
    try:
        with FAT32Parser(image_path) as fat_parser:
            boot = fat_parser.parse_boot_sector()
            print("Boot Sector:")
            print(f"  Bytes per sector: {boot.bytes_per_sector}")
            print(f"  Sectors per cluster: {boot.sectors_per_cluster}")
            print(f"  Root directory cluster: {boot.root_dir_cluster}")
            
            dir_parser = DirectoryParser(fat_parser)
            entries = dir_parser.parse_root_directory()

            print("\nRoot Directory Entries:")
            for entry in entries:
                type_str = "DIR" if entry.is_directory else "FILE"
                size = f"{entry.file_size:8d}" if not entry.is_directory else "   -"
                print(f"  {entry.full_name:12s} {type_str} Cluster:{entry.first_cluster:6d} Size:{size}")

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: test_parser.py <image>")
        sys.exit(1)
    main(sys.argv[1])

