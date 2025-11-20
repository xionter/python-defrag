#!/usr/bin/env python3
import sys
import os
import argparse
import runpy

from src import FAT32Analyzer, print_summary, DefragmentationEngine, FAT32Parser


def get_absolute_image_path(relative_path):
    project_root = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.join(project_root, relative_path)

    if not os.path.exists(abs_path):
        alt_path = os.path.join(project_root, "images", os.path.basename(relative_path))
        if os.path.exists(alt_path):
            return alt_path
        else:
            return None
    return abs_path


def _run_test_script(script_path, image_arg):
    if not os.path.exists(script_path):
        print(f"{os.path.basename(script_path)} not found\n")
        return False

    saved_argv = sys.argv
    try:
        sys.argv = [script_path, image_arg]
        try:
            runpy.run_path(script_path, run_name="__main__")
            print(f"{os.path.basename(script_path)} completed successfully\n")
            return True
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
            if code == 0:
                print(f"{os.path.basename(script_path)} completed successfully\n")
                return True
            else:
                print(f"{os.path.basename(script_path)} failed (exit {code})\n")
                return False
        except Exception as e:
            print(f"{os.path.basename(script_path)} failed: {e}\n")
            return False
    finally:
        sys.argv = saved_argv


def run_parser_test(image_path):
    print("=" * 60)
    print("TESTING PARSER MODULE")
    print("=" * 60)

    test_script = os.path.join(os.path.dirname(__file__), "tests", "test_parser.py")
    abs_image_path = get_absolute_image_path(image_path)
    if not abs_image_path:
        print("Test image not found")
        return False

    return _run_test_script(test_script, abs_image_path)


def run_analysis_test(image_path):
    print("=" * 60)
    print("TESTING ANALYSIS MODULE")
    print("=" * 60)

    test_script = os.path.join(os.path.dirname(__file__), "tests", "test_analysis.py")
    abs_image_path = get_absolute_image_path(image_path)
    if not abs_image_path:
        print("Test image not found")
        return False

    return _run_test_script(test_script, abs_image_path)


def run_integration_test(image_path):
    print("=" * 60)
    print("TESTING MODULE INTEGRATION")
    print("=" * 60)

    if FAT32Parser is None or FAT32Analyzer is None or print_summary is None:
        print("Integration test skipped: required modules not available")
        return False

    try:
        print("Testing integrated workflow...")

        abs_image_path = get_absolute_image_path(image_path)
        if not abs_image_path:
            print("Test image not found")
            return False

        with FAT32Parser(abs_image_path) as parser:
            parser.parse_boot_sector()
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()

            print_summary(report)

            assert "stats" in report, "Report missing stats"
            assert "files" in report, "Report missing files"
            assert "dirs" in report, "Report missing directories"

            print("Integration test passed")
            print(f"  - Found {report['stats']['files_total']} files")
            print(f"  - {report['stats']['files_fragmented']} fragmented files")
            print(f"  - {len(report['dirs'])} directories\n")
            return True

    except Exception as e:
        print(f"Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def run_engine_test(image_path):
    print("=" * 60)
    print("TESTING ENGINE MODULE")
    print("=" * 60)

    if FAT32Parser is None or DefragmentationEngine is None:
        print("Engine test skipped: required modules not available")
        return False

    try:
        abs_image_path = get_absolute_image_path(image_path)
        if not abs_image_path:
            print("Test image not found")
            return False

        print("Testing engine functionality...")
        with FAT32Parser(abs_image_path) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)

            # Анализ напрямую через analyzer,
            report = engine.analyzer.analyze()
            print("Analysis working")

            moves = engine.plan_defragmentation(report)
            print(f"Planning working - found {len(moves)} moves to make")

            # defragment без dry_run (новый интерфейс)
            result = engine.defragment()
            print("Defragmentation call working")

            print("Engine test completed successfully\n")
            return True

    except Exception as e:
        print(f"Engine test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def main():
    parser = argparse.ArgumentParser(description="Test entire FAT32 defragmentation project")
    parser.add_argument("--image", default="FAT_32_fragmented", help="Name of FAT32 test image in images/ folder")
    parser.add_argument("--skip-parser", action="store_true", help="Skip parser tests")
    parser.add_argument("--skip-analysis", action="store_true", help="Skip analysis tests")
    parser.add_argument("--skip-engine", action="store_true", help="Skip engine tests")

    args = parser.parse_args()

    image_relative_path = os.path.join("images", args.image)

    print(f"Looking for test image: {image_relative_path}")
    print()

    results = []

    if not args.skip_parser:
        results.append(("Parser", run_parser_test(image_relative_path)))

    if not args.skip_analysis:
        results.append(("Analysis", run_analysis_test(image_relative_path)))

    results.append(("Integration", run_integration_test(image_relative_path)))

    if not args.skip_engine:
        results.append(("Engine", run_engine_test(image_relative_path)))

    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = 0
    total = len(results)

    for test_name, success in results:
        status = "PASS" if success else "FAIL"
        print(f"{test_name:15} : {status}")
        if success:
            passed += 1

    print(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed. Project looks OK.")
        return 0
    else:
        print("Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
