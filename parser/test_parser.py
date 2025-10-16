#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(__file__))

from fat32_parser import FAT32Parser
from directory_entry import DirectoryParser

def main():
    image_path = "../images/FAT_32_32MB"
    
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
                print(f"  {entry.full_name:12s} {type_str} Cluster: {entry.first_cluster:6d} Size: {size_str}")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
