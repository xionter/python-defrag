"""Utilities for parsing FAT32 directory entries."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional


@dataclass(slots=True)
class DirectoryEntry:
    """Represents a single on-disk FAT32 directory entry."""

    name: str
    extension: str
    attributes: int
    create_time: Optional[datetime]
    modify_time: Optional[datetime]
    access_time: Optional[datetime]
    first_cluster: int
    file_size: int
    is_directory: bool
    is_volume_label: bool
    is_deleted: bool = False

    @property
    def full_name(self) -> str:
        """Return the canonical name, including the extension when present."""
        return f"{self.name}.{self.extension}" if self.extension else self.name


class DirectoryParser:
    """Parses FAT32 directory data into high-level DirectoryEntry objects."""

    ENTRY_SIZE = 32

    def __init__(self, fat_parser):
        self.fat_parser = fat_parser

    @staticmethod
    def _parse_time(
        time: int,
        date: int,
        tenths: int = 0,
    ) -> Optional[datetime]:
        """Convert FAT date/time fields into a datetime."""
        try:
            second = (time & 0x1F) * 2
            minute = (time >> 5) & 0x3F
            hour = (time >> 11) & 0x1F

            day = date & 0x1F
            month = (date >> 5) & 0x0F
            year = ((date >> 9) & 0x7F) + 1980

            if tenths > 0:
                second += tenths // 100
                microsecond = (tenths % 100) * 10_000
            else:
                microsecond = 0

            return datetime(year, month, day, hour, minute, second, microsecond)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _decode_ascii(field: bytes) -> str:
        """Decode an ASCII field and strip trailing whitespace."""
        return field.decode("ascii", errors="replace").rstrip()

    def _iter_raw_entries(self, directory_data: bytes) -> Iterable[bytes]:
        for offset in range(0, len(directory_data), self.ENTRY_SIZE):
            chunk = directory_data[offset : offset + self.ENTRY_SIZE]
            if len(chunk) < self.ENTRY_SIZE or chunk[0] == 0x00:
                break
            if chunk[0] == 0xE5 or chunk[11] == 0x0F:
                continue
            yield chunk

    def parse_directory_entries(self, cluster_data: bytes) -> List[DirectoryEntry]:
        """Parse 32-byte directory entries stored within raw cluster data."""
        entries: List[DirectoryEntry] = []
        for raw_entry in self._iter_raw_entries(cluster_data):
            entry = self._build_entry(raw_entry)
            if entry:
                entries.append(entry)
        return entries

    def _build_entry(self, entry_data: bytes) -> Optional[DirectoryEntry]:
        try:
            name = self._decode_ascii(entry_data[0:8])
            extension = self._decode_ascii(entry_data[8:11])

            attrs = entry_data[11]
            is_directory = bool(attrs & 0x10)
            is_volume_label = bool(attrs & 0x08)

            create_time_tenths = entry_data[13]
            create_time = struct.unpack("<H", entry_data[14:16])[0]
            create_date = struct.unpack("<H", entry_data[16:18])[0]
            access_date = struct.unpack("<H", entry_data[18:20])[0]
            modify_time = struct.unpack("<H", entry_data[22:24])[0]
            modify_date = struct.unpack("<H", entry_data[24:26])[0]

            first_cluster_high = struct.unpack("<H", entry_data[20:22])[0]
            first_cluster_low = struct.unpack("<H", entry_data[26:28])[0]
            first_cluster = (first_cluster_high << 16) | first_cluster_low

            file_size = struct.unpack("<I", entry_data[28:32])[0]

            return DirectoryEntry(
                name=name,
                extension=extension,
                attributes=attrs,
                create_time=self._parse_time(create_time, create_date, create_time_tenths),
                modify_time=self._parse_time(modify_time, modify_date),
                access_time=self._parse_time(0, access_date),
                first_cluster=first_cluster,
                file_size=file_size,
                is_directory=is_directory,
                is_volume_label=is_volume_label,
            )
        except (UnicodeDecodeError, struct.error):
            return None

    def parse_root_directory(self) -> List[DirectoryEntry]:
        """Parse the root directory cluster referenced by the boot sector."""
        if not self.fat_parser.boot_sector:
            self.fat_parser.parse_boot_sector()

        root_cluster = self.fat_parser.boot_sector.root_dir_cluster
        root_data = self.fat_parser.read_cluster(root_cluster)
        return self.parse_directory_entries(root_data)
