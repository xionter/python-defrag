import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

from python_defrag.analysis.analyser import FAT32Analyzer, print_summary
from python_defrag.parser.fat32_parser import FAT32Parser


def main_cli(image_path: str, top_n: int = 10) -> None:
    analyzer_report = None
    with FAT32Parser(image_path) as p:
        p.parse_boot_sector()
        ana = FAT32Analyzer(p)
        analyzer_report = ana.analyze()
    print_summary(analyzer_report)
    files = analyzer_report["files"]
    files_sorted = sorted(files, key=lambda r: r["fragments"], reverse=True)[:top_n]
    print("\nTop fragmented files:")
    for i, r in enumerate(files_sorted, 1):
        print(f"{i:2d}) {r['path']}  frags={r['fragments']}  size={r['size_bytes']} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect FAT32 fragmentation")
    parser.add_argument("image", nargs="?", default=PROJECT_ROOT / "images" / "FAT_32_32MB")
    parser.add_argument("--top", type=int, default=10, help="show top-N fragmented files")
    args = parser.parse_args()
    main_cli(str(args.image), args.top)
