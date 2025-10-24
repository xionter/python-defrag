from typing import List, Dict, Tuple, Optional
import sys
import os

# Add project paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parser')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'analysis')))

from fat32_parser import FAT32Parser
from analyser import FAT32Analyzer

class DefragmentationEngine:
    def __init__(self, parser: FAT32Parser):
        self.parser = parser
        self.analyzer = FAT32Analyzer(parser)
        
    def analyze_fragmentation(self) -> Dict:
        """Get current fragmentation state"""
        return self.analyzer.analyze()
    
    def plan_defragmentation(self, report: Dict) -> List[Dict]:
        """
        Plan the defragmentation strategy
        Returns list of move operations
        """
        print("Planning defragmentation...")
        
        moves = []
        files = report["files"]
        free_extents = report["free_extents"]
        
        # Sort files by fragmentation level (most fragmented first)
        fragmented_files = [f for f in files if f["fragments"] > 1]
        fragmented_files.sort(key=lambda x: x["fragments"], reverse=True)
        
        current_free_ptr = free_extents[0]["start_lcn"] if free_extents else 2
        
        for file_info in fragmented_files:
            clusters_needed = len(file_info["clusters"])
            
            # Check if we have enough contiguous free space
            for free_extent in free_extents:
                if free_extent["start_lcn"] >= current_free_ptr and free_extent["length"] >= clusters_needed:
                    moves.append({
                        'file_path': file_info['path'],
                        'source_clusters': file_info['clusters'],
                        'target_start': free_extent["start_lcn"],
                        'size_bytes': file_info['size_bytes'],
                        'fragments_before': file_info['fragments'],
                        'fragments_after': 1  # Will be contiguous after move
                    })
                    current_free_ptr = free_extent["start_lcn"] + clusters_needed
                    break
        
        print(f"Planned {len(moves)} file moves")
        return moves
    
    def simulate_defragmentation(self, moves: List[Dict]) -> Dict:
        """
        Simulate defragmentation without actually modifying the image
        """
        print("Simulating defragmentation...")
        
        simulation_results = {
            'total_moves': len(moves),
            'total_clusters_moved': 0,
            'fragmentation_reduction': 0,
            'files_optimized': 0
        }
        
        for move in moves:
            clusters_moved = len(move['source_clusters'])
            frag_reduction = move['fragments_before'] - move['fragments_after']
            
            simulation_results['total_clusters_moved'] += clusters_moved
            simulation_results['fragmentation_reduction'] += frag_reduction
            simulation_results['files_optimized'] += 1
            
            print(f"  Would move: {move['file_path']}")
            print(f"    From: {move['source_clusters'][:3]}... (total {len(move['source_clusters'])} clusters)")
            print(f"    To: clusters starting at {move['target_start']}")
            print(f"    Fragments: {move['fragments_before']} → {move['fragments_after']}")
            print()
        
        return simulation_results
    
    def defragment(self, dry_run: bool = True) -> Dict:
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
            # TODO: Implement actual cluster moving
            print("WARNING: Actual defragmentation not implemented yet")
            return {
                'original_report': report,
                'planned_moves': moves,
                'executed': True,
                'warning': 'Actual cluster moving not implemented'
            }
