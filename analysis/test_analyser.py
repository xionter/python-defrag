from analyser import *
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parser')))
from fat32_parser import FAT32Parser
from directory_entry import DirectoryParser


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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("image", help="FAT32 image path")
    ap.add_argument("--top", type=int, default=10, help="show top-N fragmented files")
    args = ap.parse_args()
    main_cli(args.image, args.top)
