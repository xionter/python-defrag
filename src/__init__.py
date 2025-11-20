from importlib import import_module as _import_module
from typing import Any

def _lazy_import(module_name: str) -> Any:
    return _import_module(f"{__name__}.{module_name}")


try:
    _analyser = _lazy_import("analyser")
    FAT32Analyzer = _analyser.FAT32Analyzer
    print_summary = _analyser.print_summary
except Exception:
    FAT32Analyzer = None
    print_summary = None

try:
    _parser = _lazy_import("fat32_parser")
    FAT32Parser = _parser.FAT32Parser
except Exception:
    FAT32Parser = None

try:
    _engine = _lazy_import("defrag_engine")
    DefragmentationEnginge = _engine.DefragmentationEngine
except Exception:
    DefragmentationEngine = None

try:
    _directory_entry = _lazy_import("directory_entry")
    DirectoryEntry = _directory_entry.DirectoryEntry
    DirectoryParser = _directory_entry.DirectoryParser
except Exception:
    DirectoryEntry = None
    DirectoryParser = None

__all__ = ["FAT32Analyzer", "print_summary", "FAT32Parser", "DefragmentationEngine", "DirectoryEntry", "DirectoryParser"]
