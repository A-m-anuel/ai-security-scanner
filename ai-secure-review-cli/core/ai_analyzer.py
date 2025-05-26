import asyncio
from typing import List, Dict, Any, Optional
from core.models import Vulnerability, CodeContext
from ai_models.model_interface import AIModelInterface

class AIAnalyzer:
    """Main AI-powered code analyzer - FIXED VERSION"""
    
    def __init__(self, config: Dict[str, Any], provider: str = 'huggingface', 
                 model: Optional[str] = None, pattern_only: bool = False):
        self.config = config
        self.provider = provider
        self.pattern_only = pattern_only
        self.model_name = model or config['ai_providers'][provider].get('code_model', 'microsoft/codebert-base')
        
        # Initialize AI model
        self.ai_model = self._create_ai_model(provider, config['ai_providers'][provider], pattern_only)
        
        # Analysis settings
        self.analysis_settings = config.get('analysis_settings', {})
        self.chunk_size = self.analysis_settings.get('chunk_size', 500)
        self.overlap = self.analysis_settings.get('overlap', 25)
    
    def _create_ai_model(self, provider: str, provider_config: Dict[str, Any], 
                        pattern_only: bool = False) -> AIModelInterface:
        """Create AI model instance"""
        
        if provider == 'huggingface':
            from ai_models.huggingface_analyzer import HuggingFaceAnalyzer
            return HuggingFaceAnalyzer(provider_config, pattern_only=pattern_only)
        else:
            raise ValueError(f"Unsupported AI provider: {provider}. Only 'huggingface' is supported.")
    
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities"""
        
        # For small files, analyze as whole
        lines = code.split('\n')
        if len(lines) <= self.chunk_size:
            return await self.ai_model.analyze_code(code, context)
        
        # For large files, use chunking
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
                imports=context.imports,
                functions=[],  # Simplified for now
                classes=[],   # Simplified for now
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
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        
        # Simple deduplication by type and line number
        seen = set()
        deduplicated = []
        
        for vuln in vulnerabilities:
            key = (vuln.type, vuln.location.line_number if vuln.location else 0)
            if key not in seen:
                seen.add(key)
                deduplicated.append(vuln)
        
        return deduplicated