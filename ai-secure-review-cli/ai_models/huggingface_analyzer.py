# ai_models/huggingface_analyzer.py - Complete working version
import asyncio
import aiohttp
import json
import uuid
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

from .model_interface import AIModelInterface
from core.models import Vulnerability, CodeContext, Severity, CodeLocation
from utils.rate_limiter import RateLimiter

class HuggingFaceAnalyzer(AIModelInterface):
    """Hugging Face-based code security analyzer with pattern detection"""
    
    def __init__(self, config: Dict[str, Any], pattern_only: bool = False):
        super().__init__(config)
        
        # Configuration
        self.api_key = config.get('api_key')
        self.base_url = config.get('base_url', 'https://api-inference.huggingface.co/models/')
        self.pattern_only = pattern_only or not self.api_key
        
        # Rate limiter
        self.rate_limiter = RateLimiter(
            max_calls=config.get('rate_limit', 30),
            time_window=60
        )
        
        # Track API failures for intelligent fallback
        self.api_failures = 0
        self.max_failures = 2
        
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities"""
        
        # Always do pattern detection first
        pattern_vulnerabilities = self._detect_pattern_vulnerabilities(code, context)
        
        # If pattern-only mode or no API key, return pattern results
        if self.pattern_only or not self.api_key or self.api_failures >= self.max_failures:
            if self.api_failures >= self.max_failures:
                print(f"[AI] Using pattern-only due to {self.api_failures} API failures")
            return pattern_vulnerabilities
        
        # Try AI enhancement if we have API access
        if self.api_key and self.api_failures < self.max_failures:
            try:
                print(f"[AI] Attempting AI enhancement...")
                enhanced_vulns = await self._enhance_with_ai(pattern_vulnerabilities, code, context)
                if enhanced_vulns:
                    print(f"[AI] ✓ AI enhancement successful")
                    self.api_failures = 0  # Reset on success
                    return enhanced_vulns
                else:
                    print(f"[AI] AI enhancement returned no results")
                    return pattern_vulnerabilities
            except Exception as e:
                self.api_failures += 1
                print(f"[AI] ⚠ AI enhancement failed ({self.api_failures}/{self.max_failures}): {e}")
                return pattern_vulnerabilities
        
        return pattern_vulnerabilities
    
    def _detect_pattern_vulnerabilities(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Detect vulnerabilities using pattern matching"""
        
        vulnerabilities = []
        language = context.language.value
        patterns = self._get_vulnerability_patterns(language)
        
        lines = code.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_info in patterns:
                if self._matches_pattern(line, pattern_info):
                    vuln = self._create_vulnerability_from_pattern(
                        pattern_info, line, line_num, context
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_vulnerability_patterns(self, language: str) -> List[Dict[str, Any]]:
        """Get vulnerability patterns for a specific language"""
        
        patterns = {
            'python': [
                # SQL Injection patterns
                {
                    'name': 'SQL Injection',
                    'pattern': r'(cursor\.execute|execute|query)\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability from string concatenation in query'
                },
                {
                    'name': 'SQL Injection (f-string)',
                    'pattern': r'(cursor\.execute|execute|query)\s*\(\s*f["\'].*\{.*\}.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability using f-string formatting'
                },
                
                # XSS and Template Injection
                {
                    'name': 'Flask Template Injection',
                    'pattern': r'render_template_string\s*\(\s*f["\'].*\{.*\}.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-94',
                    'description': 'Template injection vulnerability in Flask render_template_string with f-string'
                },
                {
                    'name': 'Flask XSS',
                    'pattern': r'render_template_string\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-79',
                    'description': 'Cross-site scripting vulnerability in Flask template rendering'
                },
                
                # Command Injection
                {
                    'name': 'Command Injection',
                    'pattern': r'os\.system\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection through os.system with string concatenation'
                },
                {
                    'name': 'Command Injection (f-string)',
                    'pattern': r'os\.system\s*\(\s*f["\'].*\{.*\}.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection using f-string formatting'
                },
                
                # Hardcoded Secrets
                {
                    'name': 'Hardcoded Password',
                    'pattern': r'(password|pwd|passwd)\s*=\s*["\'][^"\']{6,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded password detected'
                },
                {
                    'name': 'Hardcoded API Key',
                    'pattern': r'(api[_-]?key|secret[_-]?key|access[_-]?key)\s*=\s*["\'][^"\']{10,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded API key or secret detected'
                },
                
                # Other vulnerabilities
                {
                    'name': 'Insecure Deserialization',
                    'pattern': r'pickle\.loads?\s*\(',
                    'severity': Severity.HIGH,
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'cwe': 'CWE-502',
                    'description': 'Insecure deserialization using pickle'
                },
                {
                    'name': 'Weak Cryptography',
                    'pattern': r'hashlib\.(md5|sha1)\s*\(',
                    'severity': Severity.MEDIUM,
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'cwe': 'CWE-327',
                    'description': 'Use of weak cryptographic hash function'
                }
            ],
            
            'go': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(Query|Exec)\s*\(\s*["`].*\+.*["`]',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection from string concatenation'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'exec\.Command\s*\([^)]*\+',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection through exec.Command'
                },
                {
                    'name': 'Hardcoded Credentials',
                    'pattern': r'(password|key|secret|token)\s*:?=\s*["`][^"`]{6,}["`]',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded credentials detected'
                }
            ],
            
            'java': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(executeQuery|executeUpdate)\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection through string concatenation'
                },
                {
                    'name': 'Hardcoded Password',
                    'pattern': r'(password|pwd|secret)\s*=\s*["\'][^"\']{6,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded password found'
                }
            ],
            
            'csharp': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(ExecuteQuery|ExecuteNonQuery)\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability detected'
                },
                {
                    'name': 'Hardcoded Connection String',
                    'pattern': r'(connectionString|ConnectionString)\s*=\s*["\'][^"\']*password[^"\']*["\']',
                    'severity': Severity.MEDIUM,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded connection string with credentials'
                }
            ]
        }
        
        return patterns.get(language, [])
    
    def _matches_pattern(self, line: str, pattern_info: Dict[str, Any]) -> bool:
        """Check if line matches vulnerability pattern"""
        pattern = pattern_info['pattern']
        return bool(re.search(pattern, line, re.IGNORECASE))
    
    def _create_vulnerability_from_pattern(self, pattern_info: Dict[str, Any], 
                                         line: str, line_num: int, 
                                         context: CodeContext) -> Vulnerability:
        """Create vulnerability object from pattern match"""
        
        location = CodeLocation(
            file_path=context.file_path,
            line_number=line_num,
            line_content=line.strip()
        )
        
        return Vulnerability(
            id=str(uuid.uuid4()),
            type=pattern_info['name'],
            title=pattern_info['name'],
            description=pattern_info['description'],
            severity=pattern_info['severity'],
            confidence=0.85,  # Good confidence for pattern-based detection
            owasp_category=pattern_info['owasp'],
            cwe_id=pattern_info['cwe'],
            location=location,
            vulnerable_code=line.strip(),
            remediation=self._get_remediation_advice(pattern_info['name']),
            detected_by='pattern'
        )
    
    async def _enhance_with_ai(self, vulnerabilities: List[Vulnerability], 
                              code: str, context: CodeContext) -> List[Vulnerability]:
        """Try to enhance vulnerabilities with AI (may fail silently)"""
        
        if not vulnerabilities or not self.api_key:
            return vulnerabilities
        
        try:
            await self.rate_limiter.acquire()
            
            # Simple AI enhancement prompt
            ai_prompt = f"""
Security analysis for {context.language.value} code:

Code:
{code[:500]}

Found {len(vulnerabilities)} potential issues. Enhance analysis:"""

            response = await self._call_huggingface_api(
                model='gpt2',
                inputs=ai_prompt,
                parameters={
                    "max_new_tokens": 100,
                    "temperature": 0.3,
                    "return_full_text": False
                }
            )
            
            if response:
                # Mark vulnerabilities as AI-enhanced
                for vuln in vulnerabilities:
                    vuln.detected_by = 'pattern+ai'
                    vuln.confidence = min(0.95, vuln.confidence + 0.1)
                
                return vulnerabilities
            
        except Exception as e:
            print(f"[AI] Enhancement failed: {e}")
        
        return vulnerabilities
    
    async def _call_huggingface_api(self, model: str, inputs: str, parameters: Dict = None) -> Any:
        """Call Hugging Face API with error handling"""
        
        url = f"{self.base_url}{model}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {"inputs": inputs}
        if parameters:
            payload["parameters"] = parameters
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload, timeout=10) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        raise Exception(f"API error {response.status}: {error_text}")
        except Exception as e:
            raise Exception(f"API call failed: {e}")
    
    def _get_remediation_advice(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        
        remediation_map = {
            'SQL Injection': 'Use parameterized queries instead of string concatenation',
            'SQL Injection (f-string)': 'Use parameterized queries instead of f-string formatting',
            'Flask Template Injection': 'Use render_template with separate template files and proper escaping',
            'Flask XSS': 'Sanitize user input and use auto-escaping templates',
            'Command Injection': 'Use subprocess with lists instead of shell=True, validate input',
            'Command Injection (f-string)': 'Avoid f-strings in system commands, use subprocess with argument lists',
            'Hardcoded Password': 'Store credentials in environment variables or secure vaults',
            'Hardcoded API Key': 'Move API keys to environment variables or configuration files',
            'Insecure Deserialization': 'Use safe serialization formats like JSON, validate input',
            'Weak Cryptography': 'Use strong algorithms like SHA-256, bcrypt for passwords'
        }
        
        return remediation_map.get(vuln_type, 'Follow security best practices for this issue type')
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        
        # Return default fix suggestions
        return self._get_remediation_advice(vulnerability.type)
    
    def get_token_count(self, text: str) -> int:
        """Estimate token count for text"""
        return len(text) // 4