import sys
import os
import unittest

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'parser'))
sys.path.append(os.path.join(project_root, 'analysis'))

from fat32_parser import FAT32Parser
from analyser import FAT32Analyzer

class TestIntegration(unittest.TestCase):
    
    def setUp(self):
        self.image_path = os.path.join(project_root, "images", "FAT_32_fragmented")
        if not os.path.exists(self.image_path):
            self.skipTest("Test image not found")
    
    def test_parser_to_analyzer_flow(self):
        """Test that parser and analyzer work together"""
        with FAT32Parser(self.image_path) as parser:
            boot_sector = parser.parse_boot_sector()
            self.assertIsNotNone(boot_sector)
            
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            
            # Verify report structure
            self.assertIn('stats', report)
            self.assertIn('files', report)
            self.assertIn('dirs', report)
            self.assertIn('free_extents', report)
            
            # Verify basic statistics make sense
            stats = report['stats']
            self.assertGreaterEqual(stats['files_total'], 0)
            self.assertGreaterEqual(stats['cluster_size_bytes'], 512)
    
    def test_directory_traversal(self):
        """Test that we can traverse directories"""
        with FAT32Parser(self.image_path) as parser:
            parser.parse_boot_sector()
            analyzer = FAT32Analyzer(parser)
            records = analyzer.walk()
            
            # Should at least have root directory
            self.assertGreater(len(records), 0)
            
            # Root directory should be included
            root_dirs = [r for r in records if r.path == "/" and r.is_directory]
            self.assertEqual(len(root_dirs), 1)

if __name__ == '__main__':
    unittest.main()
