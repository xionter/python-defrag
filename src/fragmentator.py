import struct
import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from .fat32_parser import FAT32Parser
from .directory_entry import DirectoryParser

@dataclass
class FragmentationPlan:
    file_path: str
    original_clusters: List[int]
    fragmented_clusters: List[List[int]]
    new_first_cluster: int

class Fragmentator:
    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.dir_parser = DirectoryParser(parser)
        
    def find_file_entry(self, target_path: str) -> Optional[Tuple[int, int, Dict]]:
        if not self.parser.boot_sector:
            self.parser.parse_boot_sector()
            
        root_cluster = self.parser.boot_sector.root_dir_cluster
        
        return self._find_file_in_directory(root_cluster, "", target_path)
    
    def _find_file_in_directory(self, cluster: int, current_path: str, target_path: str) -> Optional[Tuple[int, int, Dict]]:
        entries = self._read_directory_entries(cluster)
        
        for entry in entries:
            if entry.name.strip() in (".", "..", ""):
                continue
                
            entry_path = f"{current_path}/{entry.full_name}" if current_path else f"/{entry.full_name}"
            
            if entry_path == target_path:
                return cluster, entry.first_cluster, {
                    'name': entry.name,
                    'extension': entry.extension,
                    'attributes': entry.attributes,
                    'file_size': entry.file_size,
                    'is_directory': entry.is_directory
                }
                
            if entry.is_directory and entry.first_cluster >= 2:
                result = self._find_file_in_directory(
                    entry.first_cluster,
                    entry_path,
                    target_path
                )
                if result:
                    return result
                    
        return None
    
    def _read_directory_entries(self, cluster: int) -> List:
        chain = self.parser.get_cluster_chain(cluster)
        data = bytearray()
        
        for c in chain:
            data.extend(self.parser.read_cluster(c))
            
        entries = self.dir_parser.parse_directory_entries(bytes(data))
        return entries
    
    def get_free_clusters(self) -> List[int]:
        if not self.parser.boot_sector:
            self.parser.parse_boot_sector()
            
        free_clusters = []
        total_clusters = self._get_total_clusters()
        
        for cluster in range(2, total_clusters + 2):
            entry = self.parser.read_fat_entry(cluster)
            if entry == 0:
                free_clusters.append(cluster)
                
        return free_clusters
    
    def _get_total_clusters(self) -> int:
        bs = self.parser.boot_sector
        data_sectors = bs.total_sectors - (bs.reserved_sectors + bs.num_fats * bs.sectors_per_fat)
        return data_sectors // bs.sectors_per_cluster
    
    def fragment_file(self, file_path: str, num_fragments: int = 2) -> Optional[FragmentationPlan]:
        if not self.parser.writable:
            raise RuntimeError("парсер должен быть в режиме чтения")
            
        if num_fragments < 2:
            raise ValueError("нужно как минимум 2 фрагмента")
            
        result = self.find_file_entry(file_path)
        if not result:
            print(f"файл не найден: {file_path}")
            return None
            
        dir_cluster, first_cluster, file_info = result
        
        if file_info['is_directory']:
            print(f"нельзя фрагментировать папку: {file_path}")
            return None
            
        original_chain = self.parser.get_cluster_chain(first_cluster)
        if not original_chain:
            print(f"у файла нет кластеров: {file_path}")
            return None
            
        if len(original_chain) < num_fragments:
            print(f"у файла всего {len(original_chain)} кластеров, нельзя фрагментировать в {num_fragments} частей")
            return None
        
        free_clusters = self.get_free_clusters()
        clusters_needed = len(original_chain)
        
        if len(free_clusters) < clusters_needed:
            print(f"не хватает свободных кластеров. нужно {clusters_needed}, доступно {len(free_clusters)}")
            return None
        
        fragmented_chains = self._split_chain_random(original_chain, num_fragments)
        
        allocated_chains = []
        current_free_idx = 0
        
        for i, chain_fragment in enumerate(fragmented_chains):
            if i == 0:
                allocated_chains.append(chain_fragment)
            else:
                needed = len(chain_fragment)
                if current_free_idx + needed > len(free_clusters):
                    print("не хватает цепочки кластеров")
                    return None
                    
                new_clusters = free_clusters[current_free_idx:current_free_idx + needed]
                allocated_chains.append(new_clusters)
                current_free_idx += needed
        
        self._relocate_data(original_chain, allocated_chains)
        
        new_first_cluster = self._update_fat_chains(allocated_chains)
        
        self._update_directory_entry(dir_cluster, first_cluster, new_first_cluster, file_info)
        
        self._free_original_clusters(original_chain, allocated_chains[0])
        
        return FragmentationPlan(
            file_path=file_path,
            original_clusters=original_chain,
            fragmented_clusters=allocated_chains,
            new_first_cluster=new_first_cluster
        )
    
    def _split_chain_random(self, chain: List[int], num_fragments: int) -> List[List[int]]:
        if len(chain) <= num_fragments:
            return [[c] for c in chain]
            
        break_points = sorted(random.sample(range(1, len(chain)), num_fragments - 1))
        fragments = []
        start = 0
        
        for break_point in break_points:
            fragments.append(chain[start:break_point])
            start = break_point
            
        fragments.append(chain[start:])
        
        return fragments
    
    def _relocate_data(self, original_chain: List[int], new_chains: List[List[int]]):
        all_data = bytearray()
        for cluster in original_chain:
            cluster_data = self.parser.read_cluster(cluster)
            all_data.extend(cluster_data)
        
        data_ptr = 0
        cluster_size = self.parser.boot_sector.sectors_per_cluster * self.parser.boot_sector.bytes_per_sector
        
        for chain in new_chains:
            for cluster in chain:
                start = data_ptr
                end = min(data_ptr + cluster_size, len(all_data))
                if start >= end:
                    break
                    
                cluster_data = all_data[start:end]
                if len(cluster_data) < cluster_size:
                    cluster_data += b'\x00' * (cluster_size - len(cluster_data))
                
                self.parser.write_cluster(cluster, cluster_data)
                data_ptr += cluster_size
    
    def _update_fat_chains(self, chains: List[List[int]]) -> int:
        first_cluster = chains[0][0] if chains else 0
        
        for i, chain in enumerate(chains):
            for j, cluster in enumerate(chain):
                if j == len(chain) - 1:
                    if i == len(chains) - 1:
                        next_cluster = 0x0FFFFFFF #конец цепи
                    else:
                        next_cluster = chains[i + 1][0]
                else:
                    next_cluster = chain[j + 1]
                
                self.parser.write_fat_entry(cluster, next_cluster)
        
        return first_cluster
    
    def _update_directory_entry(self, dir_cluster: int, old_first_cluster: int, 
                               new_first_cluster: int, file_info: Dict):
        chain = self.parser.get_cluster_chain(dir_cluster)
        dir_data = bytearray()
        
        for c in chain:
            dir_data.extend(self.parser.read_cluster(c))
        
        pos = 0
        updated = False
        
        while pos + 32 <= len(dir_data):
            entry_data = dir_data[pos:pos+32]
            
            if entry_data[0] == 0x00:
                break
                
            if entry_data[0] == 0xE5 or entry_data[11] == 0x0F:
                pos += 32
                continue
            
            name_bytes = entry_data[0:8]
            ext_bytes = entry_data[8:11]
            attr_byte = entry_data[11]
            
            current_name = name_bytes.decode('ascii', errors='ignore').rstrip()
            current_ext = ext_bytes.decode('ascii', errors='ignore').rstrip()
            
            high = struct.unpack('<H', entry_data[20:22])[0]
            low = struct.unpack('<H', entry_data[26:28])[0]
            current_first = (high << 16) | low
            
            if (current_first == old_first_cluster and 
                current_name == file_info['name'] and
                current_ext == file_info['extension'] and
                attr_byte == file_info['attributes']):
                
                new_high = (new_first_cluster >> 16) & 0xFFFF
                new_low = new_first_cluster & 0xFFFF
                
                dir_data[pos+20:pos+22] = struct.pack('<H', new_high)
                dir_data[pos+26:pos+28] = struct.pack('<H', new_low)
                updated = True
                break
                
            pos += 32
        
        if updated:
            data_ptr = 0
            cluster_size = self.parser.boot_sector.sectors_per_cluster * self.parser.boot_sector.bytes_per_sector
            
            for c in chain:
                chunk = dir_data[data_ptr:data_ptr + cluster_size]
                if len(chunk) < cluster_size:
                    chunk += b'\x00' * (cluster_size - len(chunk))
                
                self.parser.write_cluster(c, chunk)
                data_ptr += cluster_size
    
    def _free_original_clusters(self, original_chain: List[int], kept_clusters: List[int]):
        for cluster in original_chain:
            if cluster not in kept_clusters:
                self.parser.write_fat_entry(cluster, 0)
    
    def fragment_multiple_files(self, file_paths: List[str], 
                               min_fragments: int = 2, 
                               max_fragments: int = 5) -> List[FragmentationPlan]:
        plans = []
        
        for file_path in file_paths:
            num_fragments = random.randint(min_fragments, max_fragments)
            
            plan = self.fragment_file(file_path, num_fragments)
            if plan:
                plans.append(plan)
                print(f"сфрагментировали {file_path} в {num_fragments} фрагментов")
            else:
                print(f"не получилось зафрагментить{file_path}")
        
        return plans
    
    def get_file_info(self, file_path: str) -> Optional[Dict]:
        result = self.find_file_entry(file_path)
        if not result:
            return None
            
        dir_cluster, first_cluster, file_info = result
        
        chain = self.parser.get_cluster_chain(first_cluster)
        
        extents = self._calculate_extents(chain)
        
        return {
            'path': file_path,
            'first_cluster': first_cluster,
            'clusters': chain,
            'extents': extents,
            'fragments': len(extents),
            'size_bytes': file_info['file_size'],
            'is_directory': file_info['is_directory']
        }
    
    def _calculate_extents(self, chain: List[int]) -> List[Tuple[int, int]]:
        if not chain:
            return []
            
        extents = []
        start = chain[0]
        length = 1
        
        for i in range(1, len(chain)):
            if chain[i] == chain[i-1] + 1:
                length += 1
            else:
                extents.append((start, length))
                start = chain[i]
                length = 1
        
        extents.append((start, length))
        return extents
