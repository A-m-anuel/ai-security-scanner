# ai_models/model_interface.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from core.models import Vulnerability, CodeContext
import json

class AIModelInterface(ABC):
    """Abstract base class for AI model implementations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_name = config.get('model', 'unknown')
        self.max_tokens = config.get('max_tokens', 2000)
        self.temperature = config.get('temperature', 0.1)
    
    @abstractmethod
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities"""
        pass
    
    @abstractmethod
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        pass
    
    @abstractmethod
    def get_token_count(self, text: str) -> int:
        """Estimate token count for text"""
        pass
