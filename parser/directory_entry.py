import struct
from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from fat32_parser import *

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
    
    @property
    def full_name(self) -> str:
        if self.extension:
            return f"{self.name}.{self.extension}"
        return self.name

class DirectoryParser:
    
    def __init__(self, fat_parser):
        self.fat_parser = fat_parser
        
    def parse_directory_entries(self, cluster_data: bytes):
        pass
