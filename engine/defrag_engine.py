from typing import List, Dict, Tuple, Optional
import sys
import os
import shutil
import struct
from datetime import datetime

# Add project paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parser')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'analysis')))

from fat32_parser import FAT32Parser
from analyser import FAT32Analyzer

class DefragmentationEngine:
    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.analyzer = FAT32Analyzer(parser)
        self.modified_clusters = set()
        
    def analyze_fragmentation(self) -> Dict:
        """Get current fragmentation state"""
        return self.analyzer.analyze()
    
    def plan_defragmentation(self, report: Dict) -> List[Dict]:
        """
        Improved defragmentation planning strategy
        """
        print("Planning defragmentation...")
        
        moves = []
        files = report["files"]
        free_extents = report["free_extents"]
        
        if not free_extents:
            print("No free space available for defragmentation")
            return moves
        
        # Sort files by fragmentation level (most fragmented first)
        fragmented_files = [f for f in files if f["fragments"] > 1]
        if not fragmented_files:
            print("No fragmented files found")
            return moves
        
        fragmented_files.sort(key=lambda x: (x["fragments"], x["size_bytes"]), reverse=True)
        
        print(f"Found {len(fragmented_files)} fragmented files")
        print(f"Found {len(free_extents)} free extents")
        
        # Create a copy of free extents to modify during planning
        free_extents_working = [extent.copy() for extent in free_extents]
        
        # Plan moves for each fragmented file
        for file_info in fragmented_files:
            clusters_needed = len(file_info["clusters"])
            
            # Find the smallest free extent that can hold this file
            suitable_extent = None
            for extent in free_extents_working:
                if extent["length"] >= clusters_needed:
                    suitable_extent = extent
                    break
            
            if suitable_extent:
                moves.append({
                    'file_path': file_info['path'],
                    'source_clusters': file_info['clusters'],
                    'target_start': suitable_extent["start_lcn"],
                    'size_bytes': file_info['size_bytes'],
                    'fragments_before': file_info['fragments'],
                    'fragments_after': 1,  # Will be contiguous after move
                    'clusters_needed': clusters_needed,
                    'first_cluster': file_info['first_cluster']
                })
                
                # Update the free extent (simulate using the space)
                suitable_extent["start_lcn"] += clusters_needed
                suitable_extent["length"] -= clusters_needed
                
                # Remove fully used extents
                free_extents_working = [e for e in free_extents_working if e["length"] > 0]
    
        print(f"Planned {len(moves)} file moves")
        return moves
    
    def create_output_image(self, output_path: str) -> str:
        """Create a copy of the original image for modification"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not output_path:
            original_name = os.path.basename(self.parser.image_path)
            name, ext = os.path.splitext(original_name)
            output_path = f"images/{name}_defragmented_{timestamp}{ext}"
        
        # Create images directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Copy original image to output path
        shutil.copy2(self.parser.image_path, output_path)
        print(f"Created output image: {output_path}")
        return output_path
    
    def move_file_clusters(self, output_parser: FAT32Parser, move: Dict) -> bool:
        """Move clusters for a single file"""
        try:
            source_clusters = move['source_clusters']
            target_start = move['target_start']
            file_size = move['size_bytes']
            
            print(f"  Moving {len(source_clusters)} clusters for file size {file_size} bytes")
            
            # Read all data from source clusters
            file_data = bytearray()
            bytes_per_cluster = (self.parser.boot_sector.sectors_per_cluster * 
                               self.parser.boot_sector.bytes_per_sector)
            
            for i, cluster in enumerate(source_clusters):
                print(f"    Reading cluster {cluster}...")
                cluster_data = self.parser.read_cluster(cluster)
                
                if len(cluster_data) == 0:
                    print(f"    Warning: Cluster {cluster} returned empty data")
                    # Fill with zeros if read failed
                    cluster_data = b'\x00' * bytes_per_cluster
                elif len(cluster_data) != bytes_per_cluster:
                    print(f"    Warning: Cluster {cluster} has size {len(cluster_data)}, expected {bytes_per_cluster}")
                    # Pad with zeros if needed
                    if len(cluster_data) < bytes_per_cluster:
                        cluster_data += b'\x00' * (bytes_per_cluster - len(cluster_data))
                    else:
                        cluster_data = cluster_data[:bytes_per_cluster]
                
                file_data.extend(cluster_data)
            
            # Trim data to actual file size (last cluster might not be full)
            if len(file_data) > file_size:
                file_data = file_data[:file_size]
                print(f"    Trimmed data from {len(file_data)} to {file_size} bytes")
            
            # Write data to target clusters (contiguous)
            print(f"    Writing to clusters starting at {target_start}...")
            
            for i, target_cluster in enumerate(range(target_start, target_start + len(source_clusters))):
                start_pos = i * bytes_per_cluster
                end_pos = min(start_pos + bytes_per_cluster, len(file_data))
                
                if start_pos >= len(file_data):
                    break
                    
                cluster_data = file_data[start_pos:end_pos]
                
                # Pad last cluster if needed
                if len(cluster_data) < bytes_per_cluster:
                    cluster_data += b'\x00' * (bytes_per_cluster - len(cluster_data))
                
                # Write to target cluster in output image
                output_parser.write_cluster(target_cluster, cluster_data)
                self.modified_clusters.add(target_cluster)
                print(f"      Written cluster {target_cluster} ({len(cluster_data)} bytes)")
            
            # Update FAT chain in output image
            self.update_fat_chain(output_parser, target_start, len(source_clusters))
            
            # Update directory entry in output image
            self.update_directory_entry(output_parser, move['first_cluster'], target_start, move['file_path'])
            
            print(f"✓ Moved {move['file_path']}: clusters {source_clusters} → {list(range(target_start, target_start + len(source_clusters)))}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to move {move['file_path']}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def update_fat_chain(self, output_parser: FAT32Parser, start_cluster: int, length: int):
        """Update FAT to create a contiguous chain"""
        # Mark all clusters in the chain
        for i in range(length):
            current_cluster = start_cluster + i
            if i == length - 1:  # Last cluster
                next_cluster = 0x0FFFFFFF  # End of chain
            else:
                next_cluster = start_cluster + i + 1
            
            output_parser.write_fat_entry(current_cluster, next_cluster)
    
    def update_directory_entry(self, output_parser: FAT32Parser, old_first_cluster: int, new_first_cluster: int, file_path: str):
        """Update directory entry with new first cluster"""
        try:
            print(f"    Updating directory entry for {file_path}: first cluster {old_first_cluster} → {new_first_cluster}")
            
            # For now, we'll implement a simple approach that only updates root directory entries
            # In a full implementation, you'd need to traverse all directories
            
            # Read root directory
            root_cluster = output_parser.boot_sector.root_dir_cluster
            root_data = output_parser.read_cluster(root_cluster)
            
            # Parse directory entries and find the one that matches our file
            entries = self.parse_directory_entries(root_data)
            
            for i, entry_data in enumerate(entries):
                # Check if this entry has our old first cluster
                if len(entry_data) >= 32:
                    # Extract first cluster from directory entry (bytes 20-21 and 26-27)
                    first_cluster_high = struct.unpack('<H', entry_data[20:22])[0]
                    first_cluster_low = struct.unpack('<H', entry_data[26:28])[0]
                    entry_first_cluster = (first_cluster_high << 16) | first_cluster_low
                    
                    if entry_first_cluster == old_first_cluster:
                        # Update the first cluster
                        new_first_cluster_high = (new_first_cluster >> 16) & 0xFFFF
                        new_first_cluster_low = new_first_cluster & 0xFFFF
                        
                        # Update the entry data
                        updated_entry = bytearray(entry_data)
                        updated_entry[20:22] = struct.pack('<H', new_first_cluster_high)
                        updated_entry[26:28] = struct.pack('<H', new_first_cluster_low)
                        
                        # Write back the updated directory entry
                        entry_offset = i * 32
                        output_parser.file_handle.seek(output_parser.cluster_to_offset(root_cluster) + entry_offset)
                        output_parser.file_handle.write(updated_entry)
                        
                        print(f"    ✓ Updated directory entry at offset {entry_offset}")
                        return
            
            print(f"    ⚠ Could not find directory entry for cluster {old_first_cluster}")
            
        except Exception as e:
            print(f"    ⚠ Failed to update directory entry: {e}")

    def parse_directory_entries(self, directory_data: bytes) -> List[bytes]:
        """Parse directory entries from raw directory data"""
        entries = []
        pos = 0
        
        while pos + 32 <= len(directory_data):
            entry = directory_data[pos:pos+32]
            
            # Stop at end of directory marker
            if entry[0] == 0x00:
                break
                
            # Skip deleted entries and long file name entries
            if entry[0] != 0xE5 and entry[11] != 0x0F:
                entries.append(entry)
                
            pos += 32
        
        return entries

    def free_old_clusters(self, output_parser: FAT32Parser, source_clusters: List[int]):
        """Mark old clusters as free in FAT"""
        for cluster in source_clusters:
            if cluster not in self.modified_clusters:  # Don't free clusters we're still using
                output_parser.write_fat_entry(cluster, 0x00000000)  # Free cluster
    
    def execute_defragmentation(self, moves: List[Dict], output_path: str = None) -> Dict:
        """
        Execute the actual defragmentation with better error handling
        """
        print("Executing defragmentation...")
        
        # Create output image
        output_image_path = self.create_output_image(output_path)
        
        success_count = 0
        total_moves = len(moves)
        failed_moves = []
        
        try:
            with FAT32Parser(output_image_path, writable=True) as output_parser:
                output_parser.parse_boot_sector()
                
                # Verify we can read/write clusters
                test_cluster = 2  # First data cluster
                try:
                    test_data = output_parser.read_cluster(test_cluster)
                    print(f"✓ Test read cluster {test_cluster}: {len(test_data)} bytes")
                except Exception as e:
                    print(f"✗ Cannot read cluster {test_cluster}: {e}")
                    return {
                        'output_image': output_image_path,
                        'total_moves': total_moves,
                        'successful_moves': 0,
                        'success_rate': 0,
                        'error': f'Cannot read clusters: {e}'
                    }
                
                for i, move in enumerate(moves, 1):
                    print(f"\nProcessing move {i}/{total_moves}: {move['file_path']}")
                    print(f"  Source clusters: {move['source_clusters']}")
                    print(f"  Target start: {move['target_start']}")
                    print(f"  File size: {move['size_bytes']} bytes")
                    
                    if self.move_file_clusters(output_parser, move):
                        # Free the old clusters
                        self.free_old_clusters(output_parser, move['source_clusters'])
                        success_count += 1
                        print(f"  ✓ Successfully moved {move['file_path']}")
                    else:
                        failed_moves.append(move['file_path'])
                        print(f"  ✗ Failed to move {move['file_path']}")
                
                # Sync all changes to disk
                output_parser.sync()
                print("✓ All changes synced to disk")
            
        except Exception as e:
            print(f"✗ Fatal error during defragmentation: {e}")
            import traceback
            traceback.print_exc()
            return {
                'output_image': output_image_path,
                'total_moves': total_moves,
                'successful_moves': success_count,
                'success_rate': (success_count / total_moves) * 100 if total_moves > 0 else 0,
                'error': str(e),
                'failed_moves': failed_moves
            }
        
        result = {
            'output_image': output_image_path,
            'total_moves': total_moves,
            'successful_moves': success_count,
            'success_rate': (success_count / total_moves) * 100 if total_moves > 0 else 100
        }
        
        if failed_moves:
            result['failed_moves'] = failed_moves
        
        return result

    def verify_defragmentation(self, output_image_path: str) -> Dict:
        """Verify that defragmentation was successful"""
        print("Verifying defragmentation results...")
        
        with FAT32Parser(output_image_path) as verify_parser:
            verify_parser.parse_boot_sector()
            verify_analyzer = FAT32Analyzer(verify_parser)
            after_report = verify_analyzer.analyze()
            
            # Compare with original state
            original_report = self.analyze_fragmentation()
            
            improvement = {
                'files_fragmented_before': original_report['stats']['files_fragmented'],
                'files_fragmented_after': after_report['stats']['files_fragmented'],
                'fragmentation_reduction': original_report['stats']['files_fragmented'] - after_report['stats']['files_fragmented'],
                'avg_fragments_before': original_report['stats']['avg_fragments_per_file'],
                'avg_fragments_after': after_report['stats']['avg_fragments_per_file'],
                'volume_frag_index_before': original_report['stats']['volume_fragmentation_index'],
                'volume_frag_index_after': after_report['stats']['volume_fragmentation_index']
            }
            
            return {
                'after_report': after_report,
                'improvement': improvement
            }
    
    def defragment(self, output_path: str = None, dry_run: bool = True, verify: bool = True) -> Dict:
        """
        Main defragmentation method
        """
        print("=" * 60)
        print("DEFRAGMENTATION ENGINE")
        print("=" * 60)
        
        # Step 1: Analyze current state
        print("1. Analyzing fragmentation...")
        report = self.analyze_fragmentation()
        
        # Step 2: Plan moves
        print("2. Planning defragmentation...")
        moves = self.plan_defragmentation(report)
        
        if not moves:
            print("No defragmentation needed!")
            return {
                'original_report': report,
                'planned_moves': [],
                'executed': False,
                'message': 'No fragmented files found'
            }
        
        # Step 3: Execute or simulate
        if dry_run:
            print("3. Dry run - simulating moves...")
            simulation = self.simulate_defragmentation(moves)
            
            return {
                'original_report': report,
                'planned_moves': moves,
                'simulation_results': simulation,
                'executed': False
            }
        else:
            print("3. Executing defragmentation...")
            execution_result = self.execute_defragmentation(moves, output_path)
            
            result = {
                'original_report': report,
                'planned_moves': moves,
                'execution_result': execution_result,
                'executed': True
            }
            
            # Step 4: Verify results
            if verify and execution_result['successful_moves'] > 0:
                verification = self.verify_defragmentation(execution_result['output_image'])
                result['verification'] = verification
            
            return result
    
    def simulate_defragmentation(self, moves: List[Dict]) -> Dict:
        """
        Simulate defragmentation without actually modifying the image
        """
        print("Simulating defragmentation...")
        
        simulation_results = {
            'total_moves': len(moves),
            'total_clusters_moved': 0,
            'fragmentation_reduction': 0,
            'files_optimized': 0,
            'estimated_time_seconds': 0
        }
        
        for move in moves:
            clusters_moved = len(move['source_clusters'])
            frag_reduction = move['fragments_before'] - move['fragments_after']
            
            simulation_results['total_clusters_moved'] += clusters_moved
            simulation_results['fragmentation_reduction'] += frag_reduction
            simulation_results['files_optimized'] += 1
            
            # Estimate time (very rough estimate: 0.1 seconds per cluster)
            simulation_results['estimated_time_seconds'] += clusters_moved * 0.1
            
            print(f"  Would move: {move['file_path']}")
            print(f"    From: {move['source_clusters'][:3]}... (total {len(move['source_clusters'])} clusters)")
            print(f"    To: clusters starting at {move['target_start']}")
            print(f"    Fragments: {move['fragments_before']} → {move['fragments_after']}")
            print()
        
        return simulation_results
