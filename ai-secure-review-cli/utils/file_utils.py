
import os
from pathlib import Path
from typing import List, Generator
from core.language_detector import LanguageDetector

class FileUtils:
    """Utility functions for file operations"""
    
    @staticmethod
    def find_source_files(directory: str, recursive: bool = True) -> Generator[str, None, None]:
        """Find all supported source files in directory"""
        path = Path(directory)
        
        if not path.exists():
            return
        
        pattern = "**/*" if recursive else "*"
        
        for file_path in path.glob(pattern):
            if file_path.is_file() and LanguageDetector.is_supported_file(str(file_path)):
                yield str(file_path)
    
    @staticmethod
    def get_project_stats(directory: str) -> dict:
        """Get statistics about the project"""
        stats = {
            'total_files': 0,
            'by_language': {},
            'total_lines': 0
        }
        
        for file_path in FileUtils.find_source_files(directory):
            try:
                language = LanguageDetector.detect_from_file(file_path)
                if language:
                    stats['total_files'] += 1
                    lang_name = language.value
                    
                    if lang_name not in stats['by_language']:
                        stats['by_language'][lang_name] = {'files': 0, 'lines': 0}
                    
                    stats['by_language'][lang_name]['files'] += 1
                    
                    # Count lines
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = len(f.readlines())
                        stats['by_language'][lang_name]['lines'] += lines
                        stats['total_lines'] += lines
                        
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
        
        return stats
    
    @staticmethod
    def is_test_file(file_path: str) -> bool:
        """Check if file is a test file"""
        path = Path(file_path)
        
        # Common test patterns
        test_patterns = [
            'test_', '_test', 'tests/', '/test/', 
            'spec_', '_spec', 'specs/', '/spec/',
            '.test.', '.spec.'
        ]
        
        file_str = str(path).lower()
        return any(pattern in file_str for pattern in test_patterns)
    
    @staticmethod
    def should_exclude_file(file_path: str, exclude_patterns: List[str] = None) -> bool:
        """Check if file should be excluded from analysis"""
        if exclude_patterns is None:
            exclude_patterns = [
                'node_modules/', 'vendor/', '.git/', '__pycache__/',
                '.venv/', 'venv/', '.env/', 'build/', 'dist/',
                '.idea/', '.vscode/', '*.min.js', '*.bundle.js'
            ]
        
        path_str = str(Path(file_path)).lower()
        
        for pattern in exclude_patterns:
            if pattern.endswith('/'):
                # Directory pattern
                if f"/{pattern}" in path_str or path_str.startswith(pattern):
                    return True
            elif '*' in pattern:
                # Glob pattern - simple implementation
                if pattern.replace('*', '') in path_str:
                    return True
            else:
                # Simple string match
                if pattern in path_str:
                    return True
        
        return False