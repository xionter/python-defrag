#!/usr/bin/env python3
import sys
import os
import subprocess
import argparse

def get_absolute_image_path(relative_path):
    """Convert relative path to absolute path from project root"""
    project_root = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.join(project_root, relative_path)
    
    if not os.path.exists(abs_path):
        # Try without the images/ prefix
        alt_path = os.path.join(project_root, 'images', os.path.basename(relative_path))
        if os.path.exists(alt_path):
            return alt_path
        else:
            return None
    return abs_path

def run_parser_test(image_path):
    """Test the basic parser functionality"""
    print("=" * 60)
    print("TESTING PARSER MODULE")
    print("=" * 60)
    
    parser_dir = os.path.join(os.path.dirname(__file__), 'parser')
    test_script = os.path.join(parser_dir, 'test_parser.py')
    
    if os.path.exists(test_script):
        print("Running parser test...")
        try:
            # Use absolute path for the image in parser test
            abs_image_path = get_absolute_image_path(image_path)
            if not abs_image_path:
                print("✗ Test image not found")
                return False
            
            # Create a temporary test runner that uses absolute paths
            temp_test = os.path.join(parser_dir, 'temp_test.py')
            with open(test_script, 'r') as f:
                content = f.read()
            
            # Modify the test to use absolute path
            modified_content = content.replace(
                'image_path = image_path_windows if os.name == \'nt\' else image_path_linux',
                f'image_path = r"{abs_image_path}"'  # Use raw string to avoid escape issues
            )
            
            with open(temp_test, 'w') as f:
                f.write(modified_content)
            
            # Run the modified test
            original_dir = os.getcwd()
            os.chdir(parser_dir)
            subprocess.run([sys.executable, 'temp_test.py'], check=True)
            os.chdir(original_dir)
            
            # Clean up
            if os.path.exists(temp_test):
                os.remove(temp_test)
                
            print("✓ Parser test completed successfully\n")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Parser test failed: {e}\n")
            # Clean up on failure
            if os.path.exists(temp_test):
                os.remove(temp_test)
            return False
    else:
        print("✗ Parser test script not found\n")
        return False

def run_analysis_test(image_path):
    """Test the analysis module"""
    print("=" * 60)
    print("TESTING ANALYSIS MODULE") 
    print("=" * 60)
    
    analysis_dir = os.path.join(os.path.dirname(__file__), 'analysis')
    test_script = os.path.join(analysis_dir, 'test_analyser.py')
    
    if os.path.exists(test_script):
        print("Running analysis test...")
        try:
            # Use absolute path for the image
            abs_image_path = get_absolute_image_path(image_path)
            if not abs_image_path:
                print("✗ Test image not found")
                return False
            
            # Change to analysis directory to run the test
            original_dir = os.getcwd()
            os.chdir(analysis_dir)
            subprocess.run([sys.executable, 'test_analyser.py', abs_image_path, '--top', '5'], check=True)
            os.chdir(original_dir)
            print("✓ Analysis test completed successfully\n")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Analysis test failed: {e}\n")
            return False
    else:
        print("✗ Analysis test script not found\n")
        return False

def run_integration_test(image_path):
    """Test integration between modules"""
    print("=" * 60)
    print("TESTING MODULE INTEGRATION")
    print("=" * 60)
    
    try:
        # Add both parser and analysis to path
        parser_path = os.path.join(os.path.dirname(__file__), 'parser')
        analysis_path = os.path.join(os.path.dirname(__file__), 'analysis')
        sys.path.append(parser_path)
        sys.path.append(analysis_path)
        
        from fat32_parser import FAT32Parser
        from analyser import FAT32Analyzer, print_summary
        
        print("Testing integrated workflow...")
        
        abs_image_path = get_absolute_image_path(image_path)
        if not abs_image_path:
            print("✗ Test image not found")
            return False
        
        with FAT32Parser(abs_image_path) as parser:
            parser.parse_boot_sector()
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            
            print_summary(report)
            
            # Basic validation
            assert 'stats' in report, "Report missing stats"
            assert 'files' in report, "Report missing files"
            assert 'dirs' in report, "Report missing directories"
            
            print("✓ Integration test passed")
            print(f"  - Found {report['stats']['files_total']} files")
            print(f"  - {report['stats']['files_fragmented']} fragmented files")
            print(f"  - {len(report['dirs'])} directories\n")
            return True
            
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False

def run_engine_test(image_path):
    """Test the engine module"""
    print("=" * 60)
    print("TESTING ENGINE MODULE") 
    print("=" * 60)
    
    try:
        # Add all paths
        parser_path = os.path.join(os.path.dirname(__file__), 'parser')
        analysis_path = os.path.join(os.path.dirname(__file__), 'analysis')
        engine_path = os.path.join(os.path.dirname(__file__), 'engine')
        sys.path.append(parser_path)
        sys.path.append(analysis_path)
        sys.path.append(engine_path)
        
        from fat32_parser import FAT32Parser
        from defrag_engine import DefragmentationEngine
        
        abs_image_path = get_absolute_image_path(image_path)
        if not abs_image_path:
            print("✗ Test image not found")
            return False
        
        print("Testing engine functionality...")
        with FAT32Parser(abs_image_path) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            
            # Test analysis
            report = engine.analyze_fragmentation()
            print("✓ Analysis working")
            
            # Test planning
            moves = engine.plan_defragmentation(report)
            print(f"✓ Planning working - found {len(moves)} moves to make")
            
            # Test dry run
            result = engine.defragment(dry_run=True)
            print("✓ Dry run defragmentation working")
            
            print("✓ Engine test completed successfully\n")
            return True
            
    except Exception as e:
        print(f"✗ Engine test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False

def main():
    parser = argparse.ArgumentParser(description='Test entire FAT32 defragmentation project')
    parser.add_argument('--image', default='FAT_32_fragmented', 
                       help='Name of FAT32 test image in images/ folder')
    parser.add_argument('--skip-parser', action='store_true', help='Skip parser tests')
    parser.add_argument('--skip-analysis', action='store_true', help='Skip analysis tests')
    parser.add_argument('--skip-engine', action='store_true', help='Skip engine tests')
    
    args = parser.parse_args()
    
    # Construct full image path
    image_relative_path = os.path.join('images', args.image)
    
    print(f"Looking for test image: {image_relative_path}")
    print()
    
    results = []
    
    # Run tests
    if not args.skip_parser:
        results.append(('Parser', run_parser_test(image_relative_path)))
    
    if not args.skip_analysis:
        results.append(('Analysis', run_analysis_test(image_relative_path)))
    
    results.append(('Integration', run_integration_test(image_relative_path)))
    
    # Add engine test
    if not args.skip_engine:
        results.append(('Engine', run_engine_test(image_relative_path)))
    
    # Print summary
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
        print("🎉 All tests passed! Your project is ready for engine development.")
        return 0
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
