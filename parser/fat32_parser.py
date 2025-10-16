import struct
import os
from typing import BinaryIO, List, Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class BootSector:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    total_sectors: int
    sectors_per_fat: int
    root_dir_cluster: int
    signature: int

class FAT32Parser:
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.file_handle: Optional[BinaryIO] = None
        self.boot_sector: Optional[BootSector] = None
        
    def open(self) -> None:
        if not os.path.exists(self.image_path):
            raise FileNotFoundError(f"Image file not found: {self.image_path}")
        
        self.file_handle = open(self.image_path, 'rb')
        
    def close(self) -> None:
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
            
    def __enter__(self):
        self.open()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
    def parse_boot_sector(self) -> BootSector:
        if not self.file_handle:
            raise RuntimeError("File not open. Call open() first.")
            
        self.file_handle.seek(0)
        boot_data = self.file_handle.read(512)
        
        if boot_data[510] != 0x55 or boot_data[511] != 0xAA:
            raise ValueError("Invalid boot sector signature")
            
        bytes_per_sector = struct.unpack('<H', boot_data[11:13])[0]
        sectors_per_cluster = struct.unpack('<B', boot_data[13:14])[0]
        reserved_sectors = struct.unpack('<H', boot_data[14:16])[0]
        num_fats = struct.unpack('<B', boot_data[16:17])[0]
        total_sectors = struct.unpack('<I', boot_data[32:36])[0]
        sectors_per_fat = struct.unpack('<I', boot_data[36:40])[0]
        root_dir_cluster = struct.unpack('<I', boot_data[44:48])[0]
        signature = struct.unpack('<H', boot_data[510:512])[0]
        
        self.boot_sector = BootSector(
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            reserved_sectors=reserved_sectors,
            num_fats=num_fats,
            total_sectors=total_sectors,
            sectors_per_fat=sectors_per_fat,
            root_dir_cluster=root_dir_cluster,
            signature=signature
        )
        
        return self.boot_sector
    
    def get_fat_offset(self, fat_number: int = 0) -> int:
        if not self.boot_sector:
            raise RuntimeError("Boot sector not parsed")
        return self.boot_sector.reserved_sectors * self.boot_sector.bytes_per_sector
    
    def get_data_offset(self) -> int:
        if not self.boot_sector:
            raise RuntimeError("Boot sector not parsed")
        
        fat_size = self.boot_sector.num_fats * self.boot_sector.sectors_per_fat
        return (self.boot_sector.reserved_sectors + fat_size) * self.boot_sector.bytes_per_sector
    
    def cluster_to_offset(self, cluster: int) -> int:
        if cluster < 2:
            raise ValueError("Cluster numbers start from 2")
            
        data_offset = self.get_data_offset()
        cluster_size = self.boot_sector.sectors_per_cluster * self.boot_sector.bytes_per_sector
        return data_offset + (cluster - 2) * cluster_size
    
    def read_cluster(self, cluster: int) -> bytes:
        offset = self.cluster_to_offset(cluster)
        self.file_handle.seek(offset)
        
        cluster_size = (self.boot_sector.sectors_per_cluster * 
                       self.boot_sector.bytes_per_sector)
        return self.file_handle.read(cluster_size)
    
    def read_fat_entry(self, cluster: int) -> int:
        if not self.boot_sector:
            raise RuntimeError("Boot sector not parsed")
            
        fat_offset = self.get_fat_offset()
        entry_offset = cluster * 4
        
        self.file_handle.seek(fat_offset + entry_offset)
        fat_entry = struct.unpack('<I', self.file_handle.read(4))[0]
        
        return fat_entry & 0x0FFFFFFF

def main():
    image_path = "../images/FAT_32_32MB"
    
    try:
        with FAT32Parser(image_path) as parser:
            boot_sector = parser.parse_boot_sector()
            print("Boot Sector Information:")
            print(f"  Bytes per sector: {boot_sector.bytes_per_sector}")
            print(f"  Sectors per cluster: {boot_sector.sectors_per_cluster}")
            print(f"  Reserved sectors: {boot_sector.reserved_sectors}")
            print(f"  Number of FATs: {boot_sector.num_fats}")
            print(f"  Sectors per FAT: {boot_sector.sectors_per_fat}")
            print(f"  Root directory cluster: {boot_sector.root_dir_cluster}")
            print(f"  Signature: 0x{boot_sector.signature:04X}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
