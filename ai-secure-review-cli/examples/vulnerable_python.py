# ai_models/huggingface_analyzer.py - FIXED VERSION WITH ACTUAL AI CALLS
import asyncio
import aiohttp
import json
import uuid
import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from .model_interface import AIModelInterface
from core.models import Vulnerability, CodeContext, Severity, CodeLocation
from utils.rate_limiter import RateLimiter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HuggingFaceAnalyzer(AIModelInterface):
    """HuggingFace analyzer that actually uses AI for security analysis"""
    
    def __init__(self, config: Dict[str, Any], pattern_only: bool = False):
        super().__init__(config)
        
        self.api_key = config.get('api_key')
        self.base_url = config.get('base_url', 'https://api-inference.huggingface.co/models/')
        self.pattern_only = pattern_only or not self.api_key
        
        # Use models that are good for code understanding and security analysis
        self.security_model = "microsoft/codebert-base"  # For code understanding
        self.text_model = "mistralai/Mixtral-8x7B-Instruct-v0.1"  # For security analysis
        
        self.rate_limiter = RateLimiter(max_calls=10, time_window=60)
        self.session = None
        
        logger.info(f"🔧 HuggingFace Analyzer initialized. Pattern-only: {self.pattern_only}")
        if not self.pattern_only:
            logger.info(f"🤖 Using models: {self.security_model} and {self.text_model}")
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
    
    async def __aenter__(self):
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities"""
        
        logger.info(f"🔍 Analyzing {context.file_path} ({context.language.value})")
        
        vulnerabilities = []
        
        # Method 1: Pattern-based detection (always run)
        pattern_vulns = await self._detect_with_patterns(code, context)
        vulnerabilities.extend(pattern_vulns)
        logger.info(f"📋 Pattern detection: {len(pattern_vulns)} vulnerabilities found")
        
        # Method 2: AI-based detection (if API key available)
        if not self.pattern_only and self.api_key:
            try:
                ai_vulns = await self._detect_with_ai(code, context)
                vulnerabilities.extend(ai_vulns)
                logger.info(f"🤖 AI detection: {len(ai_vulns)} vulnerabilities found")
            except Exception as e:
                logger.error(f"❌ AI analysis failed: {e}")
                logger.info("Falling back to pattern-only detection")
        
        # Remove duplicates
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
        
        logger.info(f"📊 Total unique vulnerabilities: {len(unique_vulns)}")
        
        return unique_vulns
    
    async def _detect_with_ai(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Detect vulnerabilities using Hugging Face AI models"""
        
        await self._ensure_session()
        await self.rate_limiter.acquire()
        
        # Prepare the security analysis prompt
        prompt = self._build_security_prompt(code, context)
        
        # Use the text generation model for analysis
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # For better results, we'll use a model that's good at following instructions
        model_url = f"{self.base_url}{self.text_model}"
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 1000,
                "temperature": 0.1,
                "top_p": 0.95,
                "do_sample": True,
                "return_full_text": False
            }
        }
        
        try:
            async with self.session.post(model_url, headers=headers, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    # Parse the AI response
                    if isinstance(result, list) and len(result) > 0:
                        ai_response = result[0].get('generated_text', '')
                        return self._parse_ai_security_response(ai_response, context)
                    else:
                        logger.warning("Unexpected response format from Hugging Face")
                        return []
                else:
                    error_text = await response.text()
                    logger.error(f"API error {response.status}: {error_text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error calling Hugging Face API: {e}")
            return []
    
    def _build_security_prompt(self, code: str, context: CodeContext) -> str:
        """Build a prompt for security analysis"""
        
        # Limit code length to avoid token limits
        max_code_length = 2000
        if len(code) > max_code_length:
            code = code[:max_code_length] + "\n... (truncated)"
        
        prompt = f"""You are a security expert analyzing {context.language.value} code for vulnerabilities.

Analyze the following code and identify security vulnerabilities. For each vulnerability found, provide:
1. Type of vulnerability
2. Severity (Critical/High/Medium/Low)
3. Line number where it occurs
4. OWASP category
5. Brief description
6. Remediation suggestion

Code to analyze:
```{context.language.value}
{code}
```

Provide your analysis in the following JSON format:
{{
  "vulnerabilities": [
    {{
      "type": "SQL Injection",
      "severity": "High",
      "line_number": 5,
      "owasp": "A03:2021 - Injection",
      "description": "User input directly concatenated in SQL query",
      "remediation": "Use parameterized queries"
    }}
  ]
}}

Focus on real security issues, not code style. Be specific about line numbers.
"""
        
        return prompt
    
    def _parse_ai_security_response(self, ai_response: str, context: CodeContext) -> List[Vulnerability]:
        """Parse AI response into vulnerability objects"""
        
        vulnerabilities = []
        
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
                
                for vuln_data in data.get('vulnerabilities', []):
                    location = CodeLocation(
                        file_path=context.file_path,
                        line_number=vuln_data.get('line_number', 0),
                        line_content=""
                    )
                    
                    # Map severity
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'medium': Severity.MEDIUM,
                        'low': Severity.LOW
                    }
                    severity = severity_map.get(
                        vuln_data.get('severity', '').lower(), 
                        Severity.MEDIUM
                    )
                    
                    vulnerability = Vulnerability(
                        id=str(uuid.uuid4()),
                        type=vuln_data.get('type', 'Security Issue'),
                        title=vuln_data.get('type', 'Security Issue'),
                        description=vuln_data.get('description', 'AI detected security issue'),
                        severity=severity,
                        confidence=0.8,  # AI detection confidence
                        owasp_category=vuln_data.get('owasp', 'Unknown'),
                        cwe_id=None,
                        location=location,
                        vulnerable_code="",
                        remediation=vuln_data.get('remediation', ''),
                        detected_by='ai'
                    )
                    
                    vulnerabilities.append(vulnerability)
            else:
                # If no JSON found, try to parse plain text response
                logger.warning("No JSON found in AI response, trying plain text parsing")
                # You could implement plain text parsing here if needed
                
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            logger.debug(f"AI response: {ai_response[:500]}...")
        
        return vulnerabilities
    
    async def _detect_with_patterns(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Detect vulnerabilities using pattern matching"""
        
        vulnerabilities = []
        
        # Single-line patterns
        patterns = self._get_vulnerability_patterns(context.language.value)
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped:
                continue
                
            for pattern_info in patterns:
                if self._matches_pattern(line_stripped, pattern_info):
                    vuln = self._create_vulnerability_from_pattern(
                        pattern_info, line_stripped, line_num, context
                    )
                    vulnerabilities.append(vuln)
        
        # Multi-line patterns for specific cases
        if context.language.value == 'python':
            multi_line_vulns = self._detect_flask_multiline_ssti(code, context)
            vulnerabilities.extend(multi_line_vulns)
        
        return vulnerabilities
    
    def _detect_flask_multiline_ssti(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Detect Flask SSTI that spans multiple lines"""
        
        vulnerabilities = []
        lines = code.split('\n')
        
        # Track f-string variables that contain user input
        f_string_vars = {}  # var_name -> line_number
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Look for f-string assignments with user input
            f_string_pattern = r'(\w+)\s*=\s*f["\'][^"\']*\{[^}]*(?:username|user|input|request\.|\.get\(|args\.get)[^}]*\}'
            f_match = re.search(f_string_pattern, line_stripped, re.IGNORECASE)
            
            if f_match:
                var_name = f_match.group(1)
                f_string_vars[var_name] = line_num
            
            # Look for render_template_string using those variables
            template_pattern = r'render_template_string\s*\(\s*(\w+)'
            t_match = re.search(template_pattern, line_stripped)
            
            if t_match:
                used_var = t_match.group(1)
                
                if used_var in f_string_vars:
                    vuln_line = f_string_vars[used_var]
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        line_number=vuln_line,
                        line_content=lines[vuln_line - 1].strip() if vuln_line <= len(lines) else ""
                    )
                    
                    vulnerability = Vulnerability(
                        id=str(uuid.uuid4()),
                        type='Server-Side Template Injection',
                        title='Flask SSTI via f-string in render_template_string',
                        description=f'Variable "{used_var}" contains user input in f-string and is passed to render_template_string',
                        severity=Severity.HIGH,
                        confidence=0.95,
                        owasp_category='A03:2021 - Injection',
                        cwe_id='CWE-94',
                        location=location,
                        vulnerable_code=lines[vuln_line - 1].strip() if vuln_line <= len(lines) else "",
                        remediation='Use render_template with separate template files instead of render_template_string',
                        detected_by='pattern'
                    )
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_vulnerability_patterns(self, language: str) -> List[Dict[str, Any]]:
        """Get vulnerability patterns for a language"""
        
        patterns = {
            'python': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(execute|query)\s*\([^)]*\+[^)]*\)|\.format\s*\([^)]*\).*(?:SELECT|INSERT|UPDATE|DELETE)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection from string concatenation or format'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'(os\.system|subprocess\.call|subprocess\.run|exec|eval)\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection through string concatenation'
                },
                {
                    'name': 'Hardcoded Secret',
                    'pattern': r'(api[_-]?key|secret[_-]?key|password|token)\s*=\s*["\'][^"\']{10,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded credentials detected'
                },
                {
                    'name': 'Insecure Deserialization',
                    'pattern': r'pickle\.loads?\s*\(|yaml\.load\s*\(',
                    'severity': Severity.HIGH,
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'cwe': 'CWE-502',
                    'description': 'Insecure deserialization'
                },
                {
                    'name': 'Path Traversal',
                    'pattern': r'open\s*\([^)]*\+[^)]*\)|os\.path\.join\s*\([^)]*request',
                    'severity': Severity.MEDIUM,
                    'owasp': 'A01:2021 - Broken Access Control',
                    'cwe': 'CWE-22',
                    'description': 'Potential path traversal vulnerability'
                }
            ],
            'go': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(Query|Exec)\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection from string concatenation'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'exec\.Command\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection through string concatenation'
                }
            ],
            'java': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(createStatement|prepareStatement)\s*\(\s*\).*execute.*\+',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability'
                }
            ],
            'csharp': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'SqlCommand\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability'
                }
            ]
        }
        
        return patterns.get(language, [])
    
    def _matches_pattern(self, line: str, pattern_info: Dict[str, Any]) -> bool:
        """Check if line matches pattern"""
        pattern = pattern_info['pattern']
        return bool(re.search(pattern, line, re.IGNORECASE))
    
    def _create_vulnerability_from_pattern(self, pattern_info: Dict[str, Any], 
                                         line: str, line_num: int, 
                                         context: CodeContext) -> Vulnerability:
        """Create vulnerability from pattern match"""
        
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
            confidence=0.85,
            owasp_category=pattern_info['owasp'],
            cwe_id=pattern_info['cwe'],
            location=location,
            vulnerable_code=line.strip(),
            remediation='Follow security best practices for this vulnerability type',
            detected_by='pattern'
        )
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        deduplicated = []
        
        for vuln in vulnerabilities:
            key = (vuln.type, vuln.location.line_number if vuln.location else 0)
            if key not in seen:
                seen.add(key)
                deduplicated.append(vuln)
        
        return deduplicated
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        
        if self.pattern_only or not self.api_key:
            # Return generic fixes for common vulnerabilities
            fixes = {
                'SQL Injection': 'Use parameterized queries or prepared statements instead of string concatenation.',
                'Command Injection': 'Use subprocess with shell=False and pass arguments as a list.',
                'Server-Side Template Injection': 'Use render_template with separate template files instead of render_template_string.',
                'Hardcoded Secret': 'Store secrets in environment variables or secure configuration files.',
                'Insecure Deserialization': 'Use safe_load() for YAML or avoid pickle for untrusted data.',
                'Path Traversal': 'Validate and sanitize file paths, use os.path.join() safely.'
            }
            
            return fixes.get(vulnerability.type, 'Follow security best practices for this vulnerability type.')
        
        # Use AI to generate specific fix
        await self._ensure_session()
        await self.rate_limiter.acquire()
        
        prompt = f"""Fix this security vulnerability:

Vulnerability: {vulnerability.type}
Description: {vulnerability.description}
Code: {vulnerability.vulnerable_code}

Provide a secure code fix:"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        model_url = f"{self.base_url}{self.text_model}"
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 200,
                "temperature": 0.1
            }
        }
        
        try:
            async with self.session.post(model_url, headers=headers, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    if isinstance(result, list) and len(result) > 0:
                        return result[0].get('generated_text', 'Unable to generate fix.')
                    
        except Exception as e:
            logger.error(f"Error generating fix: {e}")
        
        return 'Unable to generate fix suggestion.'
    
    def get_token_count(self, text: str) -> int:
        """Estimate token count"""
        # Rough estimate: ~4 characters per token
        return len(text) // 4
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None
    # In the HuggingFaceAnalyzer class, update the __aexit__ method:
    async def close(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None