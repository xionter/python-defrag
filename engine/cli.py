#!/usr/bin/env python3
import argparse
import sys
import os

# Add project paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parser')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'analysis')))

from fat32_parser import FAT32Parser
from defrag_engine import DefragmentationEngine

def main():
    parser = argparse.ArgumentParser(description='FAT32 Defragmentation Engine')
    parser.add_argument('image', help='Path to FAT32 image file')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Plan but do not execute defragmentation (default)')
    parser.add_argument('--execute', action='store_true',
                       help='Actually execute defragmentation (DANGEROUS - not implemented yet)')
    parser.add_argument('--analyze-only', action='store_true',
                       help='Only analyze fragmentation without planning moves')
    
    args = parser.parse_args()
    
    # Validate image exists
    if not os.path.exists(args.image):
        print(f"Error: Image file not found: {args.image}")
        return 1
    
    try:
        with FAT32Parser(args.image) as fat_parser:
            fat_parser.parse_boot_sector()
            engine = DefragmentationEngine(fat_parser)
            
            if args.analyze_only:
                # Just analyze
                report = engine.analyze_fragmentation()
                from analyser import print_summary
                print_summary(report)
            else:
                # Run defragmentation (dry run by default)
                dry_run = not args.execute
                result = engine.defragment(dry_run=dry_run)
                
                # Print results
                print("\n" + "=" * 60)
                print("DEFRAGMENTATION RESULTS")
                print("=" * 60)
                
                if dry_run:
                    sim = result['simulation_results']
                    print(f"Simulation completed:")
                    print(f"  - Files to optimize: {sim['files_optimized']}")
                    print(f"  - Total clusters to move: {sim['total_clusters_moved']}")
                    print(f"  - Fragmentation reduction: {sim['fragmentation_reduction']} fragments")
                    print(f"  - Total moves planned: {sim['total_moves']}")
                else:
                    print("Defragmentation executed")
                    if 'warning' in result:
                        print(f"WARNING: {result['warning']}")
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
