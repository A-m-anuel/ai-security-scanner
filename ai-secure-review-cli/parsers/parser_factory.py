
from typing import Optional, List
from core.models import Language
from .base_parser import BaseParser
from .python_parser import PythonParser
from .go_parser import GoParser
from .java_parser import JavaParser
from .csharp_parser import CSharpParser

class ParserFactory:
    """Factory for creating language parsers"""
    
    _parsers = {
        Language.PYTHON: PythonParser,
        Language.GO: GoParser,
        Language.JAVA: JavaParser,
        Language.CSHARP: CSharpParser,
    }
    
    @classmethod
    def get_parser(cls, language: Language) -> Optional[BaseParser]:
        """Get parser for specified language"""
        parser_class = cls._parsers.get(language)
        if parser_class:
            return parser_class()
        return None
    
    @classmethod
    def get_supported_languages(cls) -> List[Language]:
        """Get list of supported languages"""
        return list(cls._parsers.keys())
    
    @classmethod
    def is_language_supported(cls, language: Language) -> bool:
        """Check if language is supported"""
        return language in cls._parsers