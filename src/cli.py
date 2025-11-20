#!/usr/bin/env python3
import argparse
import sys
import os


from .fat32_parser import FAT32Parser
from .defrag_engine import DefragmentationEngine

def main():
    parser = argparse.ArgumentParser(description='FAT32 Defragmentation Engine')
    parser.add_argument('image', help='Path to FAT32 image file')
    parser.add_argument('--output', '-o', help='Output path for defragmented image')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Plan but do not execute defragmentation (default)')
    parser.add_argument('--execute', action='store_true',
                       help='Actually execute defragmentation and create output image')
    parser.add_argument('--analyze-only', action='store_true',
                       help='Only analyze fragmentation without planning moves')
    parser.add_argument('--no-verify', action='store_true',
                       help='Skip verification after defragmentation')
    
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
                result = engine.defragment(
                    output_path=args.output,
                    dry_run=dry_run,
                    verify=not args.no_verify
                )
                
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
                    print(f"  - Estimated time: {sim['estimated_time_seconds']:.1f} seconds")
                else:
                    exec_result = result['execution_result']
                    print(f"Defragmentation executed:")
                    print(f"  - Output image: {exec_result['output_image']}")
                    print(f"  - Successful moves: {exec_result['successful_moves']}/{exec_result['total_moves']}")
                    print(f"  - Success rate: {exec_result['success_rate']:.1f}%")
                    
                    if 'verification' in result:
                        imp = result['verification']['improvement']
                        print(f"  - Fragmented files: {imp['files_fragmented_before']} → {imp['files_fragmented_after']}")
                        print(f"  - Fragmentation reduction: {imp['fragmentation_reduction']} files")
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
