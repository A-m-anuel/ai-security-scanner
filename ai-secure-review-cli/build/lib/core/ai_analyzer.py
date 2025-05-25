# core/ai_analyzer.py (Updated for Hugging Face)
import asyncio
from typing import List, Dict, Any, Optional
from core.models import Vulnerability, CodeContext
from ai_models.model_interface import AIModelInterface
from ai_models.huggingface_analyzer import HuggingFaceAnalyzer

class AIAnalyzer:
    """Main AI-powered code analyzer using Hugging Face"""
    
    def __init__(self, config: Dict[str, Any], provider: str = 'huggingface', model: Optional[str] = None):
        self.config = config
        self.provider = provider
        self.model_name = model or config['ai_providers'][provider].get('code_model', 'microsoft/CodeBERT-base')
        
        # Initialize AI model
        self.ai_model = self._create_ai_model(provider, config['ai_providers'][provider])
        
        # Analysis settings
        self.analysis_settings = config.get('analysis_settings', {})
        self.chunk_size = self.analysis_settings.get('chunk_size', 500)  # Smaller for free tier
        self.overlap = self.analysis_settings.get('overlap', 25)
    
    def _create_ai_model(self, provider: str, provider_config: Dict[str, Any]) -> AIModelInterface:
        """Create AI model instance based on provider"""
        
        if provider == 'huggingface':
            return HuggingFaceAnalyzer(provider_config)
        else:
            raise ValueError(f"Unsupported AI provider: {provider}. Only 'huggingface' is supported.")
    
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities"""
        
        # Check if code needs to be chunked
        lines = code.split('\n')
        if len(lines) <= self.chunk_size:
            # Analyze entire file at once
            return await self.ai_model.analyze_code(code, context)
        
        # Chunk the code and analyze each chunk
        vulnerabilities = []
        chunks = self._chunk_code(code, context)
        
        for chunk_info in chunks:
            chunk_vulnerabilities = await self.ai_model.analyze_code(
                chunk_info['code'], 
                chunk_info['context']
            )
            
            # Adjust line numbers based on chunk offset
            for vuln in chunk_vulnerabilities:
                if vuln.location:
                    vuln.location.line_number += chunk_info['start_line'] - 1
            
            vulnerabilities.extend(chunk_vulnerabilities)
        
        # Remove duplicates and merge similar vulnerabilities
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        return await self.ai_model.generate_fix(vulnerability, code)
    
    def get_token_count(self, text: str) -> int:
        """Get token count for text"""
        return self.ai_model.get_token_count(text)
    
    def _chunk_code(self, code: str, context: CodeContext) -> List[Dict[str, Any]]:
        """Split code into chunks for analysis"""
        lines = code.split('\n')
        chunks = []
        
        start = 0
        while start < len(lines):
            end = min(start + self.chunk_size, len(lines))
            chunk_lines = lines[start:end]
            chunk_code = '\n'.join(chunk_lines)
            
            # Create context for this chunk
            chunk_context = CodeContext(
                file_path=context.file_path,
                language=context.language,
                imports=context.imports,  # Keep original imports
                functions=self._extract_functions_in_chunk(chunk_code, context.language),
                classes=self._extract_classes_in_chunk(chunk_code, context.language),
                dependencies=context.dependencies,
                framework=context.framework,
                database_type=context.database_type
            )
            
            chunks.append({
                'code': chunk_code,
                'start_line': start + 1,
                'end_line': end,
                'context': chunk_context
            })
            
            # Move start with overlap
            start = end - self.overlap
            if start >= len(lines):
                break
        
        return chunks
    
    def _extract_functions_in_chunk(self, chunk_code: str, language) -> List[str]:
        """Extract function names from a code chunk"""
        import re
        
        functions = []
        
        if language.value == 'python':
            pattern = r'^\s*(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        elif language.value == 'go':
            pattern = r'func\s+(?:\([^)]*\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        elif language.value == 'java':
            pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:\w+\s+)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        elif language.value == 'csharp':
            pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:\w+\s+)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        else:
            return []
        
        for line in chunk_code.split('\n'):
            match = re.search(pattern, line)
            if match:
                functions.append(match.group(1))
        
        return functions
    
    def _extract_classes_in_chunk(self, chunk_code: str, language) -> List[str]:
        """Extract class names from a code chunk"""
        import re
        
        classes = []
        
        if language.value == 'python':
            pattern = r'^\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        elif language.value == 'go':
            pattern = r'type\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+struct'
        elif language.value == 'java':
            pattern = r'(?:public|private)?\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        elif language.value == 'csharp':
            pattern = r'(?:public|private)?\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        else:
            return []
        
        for line in chunk_code.split('\n'):
            match = re.search(pattern, line)
            if match:
                classes.append(match.group(1))
        
        return classes
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities from chunked analysis"""
        
        # Group vulnerabilities by type and approximate location
        vulnerability_groups = {}
        
        for vuln in vulnerabilities:
            # Create a key based on type and line number (with some tolerance)
            line_group = (vuln.location.line_number // 10) * 10 if vuln.location else 0
            key = (vuln.type, line_group, vuln.owasp_category)
            
            if key not in vulnerability_groups:
                vulnerability_groups[key] = []
            vulnerability_groups[key].append(vuln)
        
        # Keep the highest confidence vulnerability from each group
        deduplicated = []
        for group in vulnerability_groups.values():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Keep the one with highest confidence
                best_vuln = max(group, key=lambda v: v.confidence)
                deduplicated.append(best_vuln)
        
        return deduplicated



