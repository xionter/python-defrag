import os
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

from python_defrag.engine.defrag_engine import DefragmentationEngine
from python_defrag.parser.fat32_parser import FAT32Parser

class TestDefragEngine(unittest.TestCase):
    
    def setUp(self):
        self.image_path = PROJECT_ROOT / "images" / "FAT_32_fragmented"
        if not os.path.exists(self.image_path):
            self.skipTest("Test image not found")
    
    def test_engine_initialization(self):
        with FAT32Parser(str(self.image_path)) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            self.assertIsNotNone(engine)
    
    def test_analysis_method(self):
        with FAT32Parser(str(self.image_path)) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            report = engine.analyzer.analyze()
            
            self.assertIn('stats', report)
            self.assertIn('files', report)
    
    def test_planning_method(self):
        with FAT32Parser(str(self.image_path)) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            report = engine.analyzer.analyze()
            moves = engine.plan_defragmentation(report)

            self.assertIsInstance(moves, list)
            if not moves:
                return

            required_keys = {
                "file_path",
                "source_clusters",
                "target_start",
                "size_bytes",
                "fragments_before",
                "fragments_after",
            }

            for move in moves:
                self.assertTrue(required_keys.issubset(move.keys()))
                self.assertIsInstance(move["file_path"], str)
                self.assertTrue(move["file_path"])
                self.assertIsInstance(move["source_clusters"], list)
                self.assertGreater(len(move["source_clusters"]), 0)
                self.assertTrue(all(isinstance(c, int) and c >= 2 for c in move["source_clusters"]))
                self.assertIsInstance(move["target_start"], int)
                self.assertGreaterEqual(move["target_start"], 2)
                self.assertIsInstance(move["size_bytes"], int)
                self.assertGreaterEqual(move["size_bytes"], 0)
                self.assertIsInstance(move["fragments_before"], int)
                self.assertGreater(move["fragments_before"], 0)
                self.assertIsInstance(move["fragments_after"], int)
                self.assertEqual(move["fragments_after"], 1)

if __name__ == '__main__':
    unittest.main()
