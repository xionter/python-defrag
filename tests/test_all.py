#!/usr/bin/env python3
"""Convenience checks that exercise the parser, analyzer, and engine."""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from python_defrag.analysis.analyser import FAT32Analyzer, print_summary
from python_defrag.engine.defrag_engine import DefragmentationEngine
from python_defrag.parser.fat32_parser import FAT32Parser


def get_absolute_image_path(image_name: str) -> Path | None:
    candidate = PROJECT_ROOT / "images" / image_name
    return candidate if candidate.exists() else None


def run_parser_test(image_path: Path) -> bool:
    print("=" * 60)
    print("TESTING PARSER MODULE")
    print("=" * 60)
    try:
        with FAT32Parser(str(image_path)) as fat_parser:
            boot_sector = fat_parser.parse_boot_sector()
            print(f"Bytes per sector: {boot_sector.bytes_per_sector}")
            print(f"Sectors per cluster: {boot_sector.sectors_per_cluster}")
            print(f"Root directory cluster: {boot_sector.root_dir_cluster}")
        return True
    except Exception as exc:
        print(f"Parser test failed: {exc}")
        return False


def run_analysis_test(image_path: Path) -> bool:
    print("=" * 60)
    print("TESTING ANALYSIS MODULE")
    print("=" * 60)
    try:
        with FAT32Parser(str(image_path)) as parser:
            parser.parse_boot_sector()
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            print_summary(report)
        return True
    except Exception as exc:
        print(f"Analysis test failed: {exc}")
        return False


def run_integration_test(image_path: Path) -> bool:
    print("=" * 60)
    print("TESTING MODULE INTEGRATION")
    print("=" * 60)
    try:
        with FAT32Parser(str(image_path)) as parser:
            parser.parse_boot_sector()
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            assert "stats" in report
            assert "files" in report
            assert "dirs" in report
            print("Integration test passed")
            return True
    except Exception as exc:
        print(f"Integration test failed: {exc}")
        return False


def run_engine_test(image_path: Path) -> bool:
    print("=" * 60)
    print("TESTING ENGINE MODULE")
    print("=" * 60)
    try:
        with FAT32Parser(str(image_path)) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            report = engine.analyzer.analyze()
            moves = engine.plan_defragmentation(report)
            print(f"Planned moves: {len(moves)}")
        return True
    except Exception as exc:
        print(f"Engine test failed: {exc}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Test the FAT32 defragmentation project")
    parser.add_argument(
        "--image",
        default="FAT_32_fragmented",
        help="Name of FAT32 test image in the images/ folder",
    )
    parser.add_argument("--skip-parser", action="store_true", help="Skip parser tests")
    parser.add_argument("--skip-analysis", action="store_true", help="Skip analysis tests")
    parser.add_argument("--skip-engine", action="store_true", help="Skip engine tests")

    args = parser.parse_args()

    image_path = get_absolute_image_path(args.image)
    if not image_path:
        print(f"Image {args.image} not found in images/")
        return 1

    print(f"Using image: {image_path}")
    print()

    results = []

    if not args.skip_parser:
        results.append(("Parser", run_parser_test(image_path)))

    if not args.skip_analysis:
        results.append(("Analysis", run_analysis_test(image_path)))

    results.append(("Integration", run_integration_test(image_path)))

    if not args.skip_engine:
        results.append(("Engine", run_engine_test(image_path)))

    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for name, success in results:
        status = "PASS" if success else "FAIL"
        print(f"{name:15}: {status}")

    print(f"\nOverall: {passed}/{total} tests passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
