import sys
import os
import unittest


project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


from src import DefragmentationEngine, FAT32Parser

class TestDefragEngine(unittest.TestCase):
    
    def setUp(self):
        self.image_path = os.path.join(project_root, "images", "FAT_32_fragmented")
        if not os.path.exists(self.image_path):
            self.skipTest("Test image not found")
    
    def test_engine_initialization(self):
        """Test that engine can be initialized"""
        with FAT32Parser(self.image_path) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            self.assertIsNotNone(engine)
    
    def test_analysis_method(self):
        """Test that engine can analyze fragmentation"""
        with FAT32Parser(self.image_path) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            report = engine.analyze_fragmentation()
            
            self.assertIn('stats', report)
            self.assertIn('files', report)
    
    def test_planning_method(self):
        """Test that engine can plan defragmentation"""
        with FAT32Parser(self.image_path) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            report = engine.analyze_fragmentation()
            moves = engine.plan_defragmentation(report)
            
            # Should return a list (may be empty if no fragmentation)
            self.assertIsInstance(moves, list)
    
    def test_dry_run_defragmentation(self):
        """Test dry run defragmentation"""
        with FAT32Parser(self.image_path) as parser:
            parser.parse_boot_sector()
            engine = DefragmentationEngine(parser)
            result = engine.defragment(dry_run=True)
            
            self.assertIn('original_report', result)
            self.assertIn('planned_moves', result)
            self.assertIn('simulation_results', result)
            self.assertFalse(result['executed'])

if __name__ == '__main__':
    unittest.main()
