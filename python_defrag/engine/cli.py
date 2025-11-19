#!/usr/bin/env python3
"""Command-line interface for running the defragmentation engine."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from ..analysis.analyser import print_summary
from ..parser.fat32_parser import FAT32Parser
from .defrag_engine import DefragmentationEngine


def _print_plan(moves: List[dict]) -> None:
    """Render a compact table of planned moves."""
    print("\nPlanned moves:")
    for move in moves:
        print(
            f"- {move['file_path']} clusters:{len(move['source_clusters'])} "
            f"target:{move['target_start']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="FAT32 Defragmentation Engine")
    parser.add_argument("image", help="Path to FAT32 image file")
    parser.add_argument("--output", "-o", help="Output path for defragmented image")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Stop after planning, do not create a new image",
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="Only print fragmentation report",
    )
    args = parser.parse_args()

    if not os.path.exists(args.image):
        print(f"Error: Image file not found: {args.image}")
        return 1

    try:
        with FAT32Parser(args.image) as fat_parser:
            fat_parser.parse_boot_sector()
            engine = DefragmentationEngine(fat_parser)

            if args.analyze_only:
                report = engine.analyzer.analyze()
                print_summary(report)
                return 0

            report = engine.analyzer.analyze()
            moves = engine.plan_defragmentation(report)

            if not moves:
                print("The volume does not need defragmentation.")
                return 0

            if args.plan_only:
                print_summary(report)
                _print_plan(moves)
                return 0

            result = engine.defragment(args.output)
            exec_result = result["execution_result"]
            print("\n" + "=" * 60)
            print("DEFRAGMENTATION RESULTS")
            print("=" * 60)
            print(f"Output image: {exec_result['output_image']}")
            print(
                "Successful moves: "
                f"{exec_result['successful_moves']}/{exec_result['total_moves']}"
            )
            print(f"Success rate: {exec_result['success_rate']:.1f}%")

    except Exception as exc:
        print(f"Error: {exc}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
