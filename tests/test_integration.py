import os
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

from python_defrag.parser.fat32_parser import FAT32Parser
from python_defrag.analysis.analyser import FAT32Analyzer

class TestIntegration(unittest.TestCase):
    
    def setUp(self):
        self.image_path = PROJECT_ROOT / "images" / "FAT_32_fragmented"
        if not os.path.exists(self.image_path):
            self.skipTest("Test image not found")
    
    def test_parser_to_analyzer_flow(self):
        with FAT32Parser(str(self.image_path)) as parser:
            boot_sector = parser.parse_boot_sector()
            self.assertIsNotNone(boot_sector)
            
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            
            self.assertIn('stats', report)
            self.assertIn('files', report)
            self.assertIn('dirs', report)
            self.assertIn('free_extents', report)
            
            stats = report['stats']
            self.assertGreaterEqual(stats['files_total'], 0)
            self.assertGreaterEqual(stats['cluster_size_bytes'], 512)
    
    def test_directory_traversal(self):
        with FAT32Parser(str(self.image_path)) as parser:
            parser.parse_boot_sector()
            analyzer = FAT32Analyzer(parser)
            records = analyzer.walk()
            
            self.assertGreater(len(records), 0)
            
            root_dirs = [r for r in records if r.path == "/" and r.is_directory]
            self.assertEqual(len(root_dirs), 1)

if __name__ == '__main__':
    unittest.main()
