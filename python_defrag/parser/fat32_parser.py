from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, List, Optional


@dataclass(slots=True)
class BootSector:

    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    total_sectors: int
    sectors_per_fat: int
    root_dir_cluster: int
    signature: int
    fat_size: int
    data_start_sector: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


class FAT32Parser:


    def __init__(self, image_path: str, writable: bool = False):
        self.image_path = image_path
        self._file: Optional[BinaryIO] = None
        self.boot_sector: Optional[BootSector] = None
        self.writable = writable

    def open(self) -> None:
        if not os.path.exists(self.image_path):
            raise FileNotFoundError(f"Image file not found: {self.image_path}")

        mode = "r+b" if self.writable else "rb"
        self._file = open(self.image_path, mode)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> "FAT32Parser":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _require_open(self) -> BinaryIO:
        if not self._file:
            raise RuntimeError("File not open. Call open() first.")
        return self._file

    @property
    def file_handle(self) -> BinaryIO:

        return self._require_open()

    def _require_boot_sector(self) -> BootSector:
        if not self.boot_sector:
            raise RuntimeError("Boot sector not parsed")
        return self.boot_sector

    def sync(self) -> None:
        if self._file:
            self._file.flush()
            os.fsync(self._file.fileno())

    def parse_boot_sector(self) -> BootSector:
        fh = self._require_open()
        fh.seek(0)
        boot_data = fh.read(512)

        if len(boot_data) < 512:
            raise ValueError("Boot sector too small")
        if boot_data[510] != 0x55 or boot_data[511] != 0xAA:
            raise ValueError("Invalid boot sector signature")

        bytes_per_sector = struct.unpack("<H", boot_data[11:13])[0]
        sectors_per_cluster = struct.unpack("<B", boot_data[13:14])[0]
        reserved_sectors = struct.unpack("<H", boot_data[14:16])[0]
        num_fats = struct.unpack("<B", boot_data[16:17])[0]
        total_sectors = struct.unpack("<I", boot_data[32:36])[0]
        sectors_per_fat = struct.unpack("<I", boot_data[36:40])[0]
        root_dir_cluster = struct.unpack("<I", boot_data[44:48])[0]
        signature = struct.unpack("<H", boot_data[510:512])[0]

        fat_size = sectors_per_fat * bytes_per_sector
        data_start_sector = reserved_sectors + (num_fats * sectors_per_fat)

        self.boot_sector = BootSector(
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            reserved_sectors=reserved_sectors,
            num_fats=num_fats,
            total_sectors=total_sectors,
            sectors_per_fat=sectors_per_fat,
            root_dir_cluster=root_dir_cluster,
            signature=signature,
            fat_size=fat_size,
            data_start_sector=data_start_sector,
        )
        return self.boot_sector

    def get_fat_offset(self, fat_number: int = 0) -> int:
        sector = self._require_boot_sector()
        return (
            sector.reserved_sectors + fat_number * sector.sectors_per_fat
        ) * sector.bytes_per_sector

    def get_data_offset(self) -> int:
        sector = self._require_boot_sector()
        return sector.data_start_sector * sector.bytes_per_sector

    def cluster_to_offset(self, cluster: int) -> int:
        if cluster < 2:
            raise ValueError("Cluster numbers start from 2")
        sector = self._require_boot_sector()
        return self.get_data_offset() + (cluster - 2) * sector.cluster_size

    def read_cluster(self, cluster: int) -> bytes:
        fh = self._require_open()
        sector = self._require_boot_sector()
        fh.seek(self.cluster_to_offset(cluster))
        return fh.read(sector.cluster_size)

    def write_cluster(self, cluster: int, data: bytes) -> None:
        if not self.writable:
            raise RuntimeError("Parser not opened in writable mode")

        fh = self._require_open()
        sector = self._require_boot_sector()
        if len(data) != sector.cluster_size:
            raise ValueError(
                f"Data size {len(data)} doesn't match cluster size {sector.cluster_size}"
            )

        fh.seek(self.cluster_to_offset(cluster))
        fh.write(data)

    def read_fat_entry(self, cluster: int) -> int:
        fh = self._require_open()
        fat_offset = self.get_fat_offset()
        entry_offset = cluster * 4

        fh.seek(fat_offset + entry_offset)
        fat_entry = struct.unpack("<I", fh.read(4))[0]
        return fat_entry & 0x0FFFFFFF

    def write_fat_entry(self, cluster: int, value: int) -> None:
        if not self.writable:
            raise RuntimeError("Parser not opened in writable mode")

        fh = self._require_open()
        sector = self._require_boot_sector()

        for fat_idx in range(sector.num_fats):
            fat_offset = self.get_fat_offset(fat_idx)
            entry_offset = cluster * 4
            fh.seek(fat_offset + entry_offset)
            fh.write(struct.pack("<I", value & 0x0FFFFFFF))

    def get_cluster_chain(self, start_cluster: int) -> List[int]:
        chain = [start_cluster]
        current = start_cluster

        while True:
            next_cluster = self.read_fat_entry(current)
            if next_cluster in (0, 1) or next_cluster >= 0x0FFFFFF8:
                break
            chain.append(next_cluster)
            current = next_cluster

        return chain
