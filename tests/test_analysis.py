from src import FAT32Analyzer, print_summary, FAT32Parser


def main_cli(image_path: str, top_n: int = 10) -> None:
    with FAT32Parser(image_path) as p:
        p.parse_boot_sector()
        ana = FAT32Analyzer(p)
        report = ana.analyze()

    print_summary(report)
    files = report["files"]
    files_sorted = sorted(files, key=lambda r: r["fragments"], reverse=True)[:top_n]

    print("\nTop fragmented files:")
    for i, r in enumerate(files_sorted, 1):
        print(f"{i:2d}) {r['path']}  frags={r['fragments']}  size={r['size_bytes']} bytes")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()
    main_cli(args.image, args.top)

