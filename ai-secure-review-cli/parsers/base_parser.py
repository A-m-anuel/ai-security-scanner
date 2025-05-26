
"""
Language parsers for extracting code context and structure
"""

# parsers/base_parser.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from core.models import CodeContext, Language

class BaseParser(ABC):
    """Abstract base class for language parsers"""
    
    def __init__(self, language: Language):
        self.language = language
    
    @abstractmethod
    def parse_file(self, file_path: str) -> CodeContext:
        """Parse a file and extract context information"""
        pass
    
    @abstractmethod
    def extract_functions(self, code: str) -> List[str]:
        """Extract function names from code"""
        pass
    
    @abstractmethod
    def extract_imports(self, code: str) -> List[str]:
        """Extract import statements from code"""
        pass
    
    @abstractmethod
    def extract_classes(self, code: str) -> List[str]:
        """Extract class names from code"""
        pass
    
    def chunk_code(self, code: str, max_lines: int = 800, overlap: int = 50) -> List[Dict[str, Any]]:
        """Split code into chunks for AI analysis"""
        lines = code.split('\n')
        chunks = []
        
        if len(lines) <= max_lines:
            return [{'code': code, 'start_line': 1, 'end_line': len(lines)}]
        
        start = 0
        while start < len(lines):
            end = min(start + max_lines, len(lines))
            chunk_lines = lines[start:end]
            
            chunks.append({
                'code': '\n'.join(chunk_lines),
                'start_line': start + 1,
                'end_line': end
            })
            
            # Move start with overlap
            start = end - overlap
            if start >= len(lines):
                break
        
        return chunks




