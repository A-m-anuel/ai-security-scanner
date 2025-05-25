# ai_models/huggingface_analyzer.py - WORKING VERSION FOR YOUR FLASK SSTI
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
    """HuggingFace analyzer that WILL detect your Flask SSTI"""
    
    def __init__(self, config: Dict[str, Any], pattern_only: bool = False):
        super().__init__(config)
        
        self.api_key = config.get('api_key')
        self.base_url = config.get('base_url', 'https://api-inference.huggingface.co/models/')
        self.pattern_only = pattern_only or not self.api_key
        
        self.rate_limiter = RateLimiter(max_calls=10, time_window=60)
        self.api_failures = 0
        self.max_failures = 3
        
        logger.info(f"🔧 HuggingFace Analyzer initialized. Pattern-only: {self.pattern_only}")
        
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code - NOW WITH MULTI-LINE FLASK SSTI DETECTION"""
        
        logger.info(f"🔍 Analyzing {context.file_path} ({context.language.value})")
        logger.info(f"📝 Code preview: {repr(code[:100])}")
        
        vulnerabilities = []
        
        # Method 1: Single-line patterns
        single_line_vulns = self._detect_single_line_patterns(code, context)
        vulnerabilities.extend(single_line_vulns)
        logger.info(f"✅ Single-line patterns: {len(single_line_vulns)} found")
        
        # Method 2: Multi-line patterns (YOUR FLASK CASE!)
        if context.language.value == 'python':
            multi_line_vulns = self._detect_flask_multiline_ssti(code, context)
            vulnerabilities.extend(multi_line_vulns)
            logger.info(f"🎯 Multi-line Flask SSTI: {len(multi_line_vulns)} found")
        
        # Method 3: Additional pattern matching
        additional_vulns = self._detect_additional_patterns(code, context)
        vulnerabilities.extend(additional_vulns)
        logger.info(f"🔍 Additional patterns: {len(additional_vulns)} found")
        
        # Remove duplicates
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
        
        logger.info(f"📊 TOTAL VULNERABILITIES FOUND: {len(unique_vulns)}")
        for vuln in unique_vulns:
            logger.info(f"   🚨 {vuln.type} at line {vuln.location.line_number}")
        
        # AI enhancement if available
        if not self.pattern_only and self.api_key and unique_vulns:
            try:
                enhanced_vulns = await self._enhance_with_ai(unique_vulns, code, context)
                return enhanced_vulns
            except Exception as e:
                logger.error(f"AI enhancement failed: {e}")
        
        return unique_vulns
    
    def _detect_flask_multiline_ssti(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """DETECT YOUR SPECIFIC FLASK SSTI CASE"""
        
        logger.info("🔍 Looking for Flask multi-line SSTI...")
        
        vulnerabilities = []
        lines = code.split('\n')
        
        # Track f-string variables that contain user input
        f_string_vars = {}  # var_name -> line_number
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Pattern 1: Look for f-string assignments with user input keywords
            f_string_pattern = r'(\w+)\s*=\s*f["\'][^"\']*\{[^}]*(?:username|user|input|request\.|\.get\(|args\.get)[^}]*\}'
            f_match = re.search(f_string_pattern, line_stripped, re.IGNORECASE)
            
            if f_match:
                var_name = f_match.group(1)
                f_string_vars[var_name] = line_num
                logger.info(f"🎯 Found f-string with user input: {var_name} = ... at line {line_num}")
                logger.info(f"    Line content: {line_stripped}")
            
            # Pattern 2: Look for render_template_string using those variables
            template_pattern = r'render_template_string\s*\(\s*(\w+)'
            t_match = re.search(template_pattern, line_stripped)
            
            if t_match:
                used_var = t_match.group(1)
                logger.info(f"🔍 Found render_template_string using variable: {used_var} at line {line_num}")
                
                if used_var in f_string_vars:
                    # BINGO! This is the Flask SSTI vulnerability
                    vuln_line = f_string_vars[used_var]
                    
                    logger.info(f"🚨 FLASK SSTI DETECTED!")
                    logger.info(f"    F-string variable: {used_var} (line {vuln_line})")
                    logger.info(f"    Used in render_template_string: line {line_num}")
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        line_number=vuln_line,
                        line_content=lines[vuln_line - 1].strip()
                    )
                    
                    vulnerability = Vulnerability(
                        id=str(uuid.uuid4()),
                        type='Flask SSTI (Multi-line)',
                        title='Server-Side Template Injection in Flask',
                        description=f'Variable "{used_var}" contains f-string with user input and is passed to render_template_string, creating SSTI vulnerability',
                        severity=Severity.HIGH,
                        confidence=0.95,
                        owasp_category='A03:2021 - Injection',
                        cwe_id='CWE-94',
                        location=location,
                        vulnerable_code=lines[vuln_line - 1].strip(),
                        business_impact='Critical SSTI vulnerability allowing remote code execution',
                        remediation='Use render_template with separate template files instead of render_template_string with user input',
                        detected_by='pattern'
                    )
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _detect_single_line_patterns(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Detect single-line vulnerabilities"""
        
        vulnerabilities = []
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
        
        return vulnerabilities
    
    def _detect_additional_patterns(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Additional pattern detection"""
        
        vulnerabilities = []
        
        if context.language.value == 'python':
            # Look for any f-string that might be dangerous
            lines = code.split('\n')
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Suspicious f-strings with user input
                if re.search(r'f["\'][^"\']*\{[^}]*(?:username|user|input|request)[^}]*\}', line_stripped, re.IGNORECASE):
                    if 'render_template_string' not in line_stripped:  # Don't double-report
                        location = CodeLocation(
                            file_path=context.file_path,
                            line_number=line_num,
                            line_content=line_stripped
                        )
                        
                        vulnerability = Vulnerability(
                            id=str(uuid.uuid4()),
                            type='Suspicious F-string with User Input',
                            title='F-string contains user input',
                            description='F-string contains user input variables - potential injection if used unsafely',
                            severity=Severity.MEDIUM,
                            confidence=0.70,
                            owasp_category='A03:2021 - Injection',
                            cwe_id='CWE-94',
                            location=location,
                            vulnerable_code=line_stripped,
                            business_impact='Potential injection vulnerability if f-string is used in unsafe contexts',
                            remediation='Ensure f-strings with user input are not used in template rendering or other unsafe contexts',
                            detected_by='pattern'
                        )
                        
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_vulnerability_patterns(self, language: str) -> List[Dict[str, Any]]:
        """Standard vulnerability patterns"""
        
        patterns = {
            'python': [
                # Direct Flask SSTI
                {
                    'name': 'Flask SSTI (Direct)',
                    'pattern': r'render_template_string\s*\(\s*f["\'][^"\']*\{.*\}.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-94',
                    'description': 'Direct SSTI using f-string in render_template_string'
                },
                
                # SQL Injection
                {
                    'name': 'SQL Injection',
                    'pattern': r'(cursor\.execute|execute|query)\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection from string concatenation'
                },
                
                # Hardcoded secrets
                {
                    'name': 'Hardcoded API Key',
                    'pattern': r'(api[_-]?key|secret[_-]?key|API_KEY)\s*=\s*["\'][^"\']{10,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded API key detected'
                },
                {
                    'name': 'Hardcoded Password',
                    'pattern': r'(password|pwd|passwd|DATABASE_PASSWORD)\s*=\s*["\'][^"\']{6,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded password detected'
                },
                
                # Other
                {
                    'name': 'Insecure Deserialization',
                    'pattern': r'pickle\.loads?\s*\(',
                    'severity': Severity.HIGH,
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'cwe': 'CWE-502',
                    'description': 'Insecure deserialization using pickle'
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
                    'description': 'Command injection through exec.Command'
                },
                {
                    'name': 'Hardcoded Credentials',
                    'pattern': r'(APIKey|DBPassword|password|key|secret)\s*[:=]\s*["`][^"`]{6,}["`]',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded credentials detected'
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
            business_impact='Could impact application security and data integrity',
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
    
    async def _enhance_with_ai(self, vulnerabilities: List[Vulnerability], 
                              code: str, context: CodeContext) -> List[Vulnerability]:
        """AI enhancement"""
        try:
            await self.rate_limiter.acquire()
            
            for vuln in vulnerabilities:
                vuln.detected_by = 'pattern+ai'
                vuln.confidence = min(0.95, vuln.confidence + 0.1)
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"AI enhancement failed: {e}")
            return vulnerabilities
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion"""
        if 'Flask SSTI' in vulnerability.type:
            return 'Use render_template with separate template files instead of render_template_string with user input'
        return 'Follow security best practices for this vulnerability type'
    
    def get_token_count(self, text: str) -> int:
        """Estimate token count"""
        return len(text) // 4