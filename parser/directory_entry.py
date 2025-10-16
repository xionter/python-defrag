import struct
from dataclasses import dataclass
from typing import Optional, List
from datetime import datetime

@dataclass
class DirectoryEntry:
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
        if self.extension:
            return f"{self.name}.{self.extension}"
        return self.name

class DirectoryParser:
    
    def __init__(self, fat_parser):
        self.fat_parser = fat_parser
        
    def _parse_fat_time_date(self, time: int, date: int, tenths: int = 0) -> Optional[datetime]:
        try:
            second = (time & 0x1F) * 2
            minute = (time >> 5) & 0x3F
            hour = (time >> 11) & 0x1F
            
            day = date & 0x1F
            month = (date >> 5) & 0x0F
            year = ((date >> 9) & 0x7F) + 1980
            
            if tenths > 0:
                second += tenths // 100
                microsecond = (tenths % 100) * 10000
            else:
                microsecond = 0
                
            return datetime(year, month, day, hour, minute, second, microsecond)
        except (ValueError, TypeError):
            return None
        
    def parse_directory_entries(self, cluster_data: bytes) -> List[DirectoryEntry]:
        entries = []
        pos = 0
        
        while pos + 32 <= len(cluster_data):
            entry_data = cluster_data[pos:pos+32]
            
            if entry_data[0] == 0x00:
                break
                
            if entry_data[0] == 0xE5:
                pos += 32
                continue
            
            attributes = entry_data[11]
            if attributes == 0x0F:
                pos += 32
                continue
            
            try:
                name_bytes = entry_data[0:8]
                ext_bytes = entry_data[8:11]
                
                name = name_bytes.decode('ascii', errors='replace').rstrip()
                extension = ext_bytes.decode('ascii', errors='replace').rstrip()
                
                attrs = attributes
                is_directory = bool(attrs & 0x10)
                is_volume_label = bool(attrs & 0x08)
                
                create_time_tenths = entry_data[13]
                create_time = struct.unpack('<H', entry_data[14:16])[0]
                create_date = struct.unpack('<H', entry_data[16:18])[0]
                access_date = struct.unpack('<H', entry_data[18:20])[0]
                modify_time = struct.unpack('<H', entry_data[22:24])[0]
                modify_date = struct.unpack('<H', entry_data[24:26])[0]
                
                first_cluster_high = struct.unpack('<H', entry_data[20:22])[0]
                first_cluster_low = struct.unpack('<H', entry_data[26:28])[0]
                first_cluster = (first_cluster_high << 16) | first_cluster_low
                
                file_size = struct.unpack('<I', entry_data[28:32])[0]
                
                create_dt = self._parse_fat_time_date(create_time, create_date, create_time_tenths)
                modify_dt = self._parse_fat_time_date(modify_time, modify_date)
                access_dt = self._parse_fat_time_date(0, access_date)
                
                entry = DirectoryEntry(
                    name=name,
                    extension=extension,
                    attributes=attrs,
                    create_time=create_dt,
                    modify_time=modify_dt,
                    access_time=access_dt,
                    first_cluster=first_cluster,
                    file_size=file_size,
                    is_directory=is_directory,
                    is_volume_label=is_volume_label
                )
                
                entries.append(entry)
                
            except (UnicodeDecodeError, struct.error) as e:
                print(f"Error parsing directory entry at offset {pos}: {e}")
                
            pos += 32
            
        return entries
    
    def parse_root_directory(self) -> List[DirectoryEntry]:
        if not self.fat_parser.boot_sector:
            self.fat_parser.parse_boot_sector()
            
        root_cluster = self.fat_parser.boot_sector.root_dir_cluster
        root_data = self.fat_parser.read_cluster(root_cluster)
        return self.parse_directory_entries(root_data)
