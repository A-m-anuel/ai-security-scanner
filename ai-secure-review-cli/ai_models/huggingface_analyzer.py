# ai_models/huggingface_analyzer.py - IMPROVED LINE DETECTION VERSION
import asyncio
import aiohttp
import json
import uuid
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from .model_interface import AIModelInterface
from core.models import Vulnerability, CodeContext, Severity, CodeLocation
from utils.rate_limiter import RateLimiter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HuggingFaceAnalyzer(AIModelInterface):
    """HuggingFace analyzer with enhanced line detection capabilities"""
    
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
            self.session = None
    
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities with enhanced line tracking"""
        
        logger.info(f"🔍 Analyzing {context.file_path} ({context.language.value})")
        
        # Create comprehensive line mapping
        lines = code.split('\n')
        line_mapping = self._create_line_mapping(lines)
        
        vulnerabilities = []
        
        # Method 1: Enhanced pattern-based detection with line tracking
        pattern_vulns = await self._detect_with_patterns_enhanced(code, context, line_mapping)
        vulnerabilities.extend(pattern_vulns)
        logger.info(f"📋 Pattern detection: {len(pattern_vulns)} vulnerabilities found")
        
        # Method 2: AI-based detection with line numbers
        if not self.pattern_only and self.api_key:
            try:
                ai_vulns = await self._detect_with_ai_enhanced(code, context, line_mapping)
                vulnerabilities.extend(ai_vulns)
                logger.info(f"🤖 AI detection: {len(ai_vulns)} vulnerabilities found")
            except Exception as e:
                logger.error(f"❌ AI analysis failed: {e}")
                logger.info("Falling back to pattern-only detection")
        
        # Enhance all vulnerabilities with accurate line information
        for vuln in vulnerabilities:
            self._enhance_vulnerability_location(vuln, line_mapping)
        
        # Remove duplicates
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
        
        logger.info(f"📊 Total unique vulnerabilities: {len(unique_vulns)}")
        for vuln in unique_vulns:
            if vuln.location:
                logger.info(f"   🚨 {vuln.type} at line {vuln.location.line_number}: {vuln.location.line_content[:50]}...")
        
        return unique_vulns
    
    def _create_line_mapping(self, lines: List[str]) -> Dict[int, Dict[str, Any]]:
        """Create a comprehensive line mapping with metadata"""
        line_mapping = {}
        for i, line in enumerate(lines):
            line_num = i + 1
            line_mapping[line_num] = {
                'content': line,
                'stripped': line.strip(),
                'indent': len(line) - len(line.lstrip()),
                'is_empty': not line.strip(),
                'is_comment': line.strip().startswith('#') if line.strip() else False
            }
        return line_mapping
    
    def _enhance_vulnerability_location(self, vuln: Vulnerability, line_mapping: Dict[int, Dict[str, Any]]):
        """Enhance vulnerability with accurate line information"""
        if vuln.location and vuln.location.line_number:
            line_num = vuln.location.line_number
            if line_num in line_mapping:
                line_info = line_mapping[line_num]
                vuln.location.line_content = line_info['content']
                
                # Add code context (surrounding lines)
                context_lines = []
                for i in range(max(1, line_num - 2), min(len(line_mapping) + 1, line_num + 3)):
                    prefix = ">> " if i == line_num else "   "
                    if i in line_mapping:
                        context_lines.append(f"{i:4d} | {prefix}{line_mapping[i]['content']}")
                
                vuln.vulnerable_code = "\n".join(context_lines)
    
    async def _detect_with_patterns_enhanced(self, code: str, context: CodeContext, 
                                           line_mapping: Dict[int, Dict[str, Any]]) -> List[Vulnerability]:
        """Enhanced pattern detection with better line tracking"""
        
        vulnerabilities = []
        patterns = self._get_enhanced_vulnerability_patterns(context.language.value)
        
        # Single-line pattern detection with column tracking
        for line_num, line_info in line_mapping.items():
            if line_info['is_empty'] or line_info['is_comment']:
                continue
            
            line_content = line_info['content']
            
            for pattern_info in patterns:
                match = re.search(pattern_info['pattern'], line_content, re.IGNORECASE)
                if match:
                    location = CodeLocation(
                        file_path=context.file_path,
                        line_number=line_num,
                        column=match.start() + 1,  # Column position
                        line_content=line_content.strip()
                    )
                    
                    vulnerability = Vulnerability(
                        id=str(uuid.uuid4()),
                        type=pattern_info['name'],
                        title=pattern_info['name'],
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        confidence=pattern_info.get('confidence', 0.85),
                        owasp_category=pattern_info['owasp'],
                        cwe_id=pattern_info['cwe'],
                        location=location,
                        vulnerable_code=match.group(0),  # Exact matched code
                        attack_vector=pattern_info.get('attack_vector', ''),
                        remediation=pattern_info.get('remediation', 'Follow security best practices'),
                        detected_by='pattern'
                    )
                    
                    vulnerabilities.append(vulnerability)
                    logger.debug(f"Found {pattern_info['name']} at line {line_num}, column {match.start() + 1}")
        
        # Multi-line pattern detection
        if context.language.value == 'python':
            multi_vulns = self._detect_multiline_vulnerabilities_enhanced(code, context, line_mapping)
            vulnerabilities.extend(multi_vulns)
        
        return vulnerabilities
    
    def _detect_multiline_vulnerabilities_enhanced(self, code: str, context: CodeContext,
                                                 line_mapping: Dict[int, Dict[str, Any]]) -> List[Vulnerability]:
        """Enhanced multi-line vulnerability detection"""
        
        vulnerabilities = []
        
        # Flask SSTI detection with better tracking
        if 'flask' in str(context.imports).lower() or context.framework == 'flask':
            flask_vulns = self._detect_flask_ssti_enhanced(line_mapping, context)
            vulnerabilities.extend(flask_vulns)
        
        # Add more multi-line patterns here
        # Example: Track variable flow across lines
        tainted_vars = self._track_tainted_variables(line_mapping, context)
        for var_name, var_info in tainted_vars.items():
            if var_info['is_vulnerable']:
                vulnerabilities.append(var_info['vulnerability'])
        
        return vulnerabilities
    
    def _detect_flask_ssti_enhanced(self, line_mapping: Dict[int, Dict[str, Any]], 
                                   context: CodeContext) -> List[Vulnerability]:
        """Enhanced Flask SSTI detection with better line tracking"""
        
        vulnerabilities = []
        
        # Track variables and their sources with more detail
        tainted_vars = {}  # var_name -> {line_num, source_type, full_line, confidence}
        
        for line_num, line_info in line_mapping.items():
            line_content = line_info['content']
            line_stripped = line_info['stripped']
            
            # Enhanced patterns for user input detection
            user_input_patterns = [
                # Direct request access
                (r'(\w+)\s*=\s*request\.(?:args|form|values|data)\.get\s*\(\s*[\'"](\w+)[\'"]', 'request_get', 0.95),
                (r'(\w+)\s*=\s*request\.(?:args|form|values|data)\[', 'request_bracket', 0.95),
                
                # F-string patterns
                (r'(\w+)\s*=\s*f["\'][^"\']*\{[^}]*\}[^"\']*["\']', 'f_string', 0.85),
                
                # Format string patterns
                (r'(\w+)\s*=\s*["\'][^"\']*\{[^}]*\}[^"\']*["\']\.format\(', 'format_string', 0.85),
                
                # Variable assignment from another tainted variable
                (r'(\w+)\s*=\s*(\w+)', 'variable_assignment', 0.7),
            ]
            
            for pattern, source_type, confidence in user_input_patterns:
                match = re.search(pattern, line_content)
                if match:
                    var_name = match.group(1)
                    
                    # Check if it's a variable assignment from another tainted var
                    if source_type == 'variable_assignment' and match.group(2) in tainted_vars:
                        parent_var = match.group(2)
                        tainted_vars[var_name] = {
                            'line_num': line_num,
                            'source_type': f'{source_type}_from_{parent_var}',
                            'full_line': line_content,
                            'confidence': tainted_vars[parent_var]['confidence'] * 0.9,
                            'parent': parent_var
                        }
                    else:
                        tainted_vars[var_name] = {
                            'line_num': line_num,
                            'source_type': source_type,
                            'full_line': line_content,
                            'confidence': confidence
                        }
                    
                    logger.debug(f"Found potentially tainted variable '{var_name}' at line {line_num} (type: {source_type})")
            
            # Check for render_template_string with enhanced detection
            render_patterns = [
                (r'render_template_string\s*\(\s*([^)]+)\)', 'direct'),
                (r'return\s+render_template_string\s*\(\s*([^)]+)\)', 'return'),
                (r'response\s*=\s*render_template_string\s*\(\s*([^)]+)\)', 'assignment'),
            ]
            
            for render_pattern, render_type in render_patterns:
                render_match = re.search(render_pattern, line_content)
                
                if render_match:
                    render_arg = render_match.group(1).strip()
                    
                    # Check if it's a direct f-string
                    if render_arg.startswith(('f"', "f'")):
                        location = CodeLocation(
                            file_path=context.file_path,
                            line_number=line_num,
                            column=render_match.start() + 1,
                            line_content=line_stripped
                        )
                        
                        vulnerability = Vulnerability(
                            id=str(uuid.uuid4()),
                            type='Server-Side Template Injection',
                            title='Direct SSTI in render_template_string',
                            description=f'F-string passed directly to render_template_string ({render_type})',
                            severity=Severity.HIGH,
                            confidence=0.95,
                            owasp_category='A03:2021 - Injection',
                            cwe_id='CWE-94',
                            location=location,
                            vulnerable_code=line_content,
                            attack_vector='Attacker can inject Jinja2 template syntax to execute arbitrary code',
                            remediation='Use render_template with separate template files',
                            detected_by='pattern'
                        )
                        vulnerabilities.append(vulnerability)
                    
                    # Check if it uses a tainted variable
                    for var_name, var_info in tainted_vars.items():
                        if var_name in render_arg:
                            location = CodeLocation(
                                file_path=context.file_path,
                                line_number=var_info['line_num'],
                                line_content=var_info['full_line'].strip()
                            )
                            
                            vulnerability = Vulnerability(
                                id=str(uuid.uuid4()),
                                type='Server-Side Template Injection',
                                title=f'SSTI via tainted variable "{var_name}"',
                                description=f'Variable "{var_name}" ({var_info["source_type"]}) from line {var_info["line_num"]} is used in render_template_string at line {line_num}',
                                severity=Severity.HIGH,
                                confidence=var_info['confidence'],
                                owasp_category='A03:2021 - Injection',
                                cwe_id='CWE-94',
                                location=location,
                                vulnerable_code=self._get_multiline_context(line_mapping, var_info['line_num'], line_num),
                                attack_vector='User input flows into template rendering, allowing template injection',
                                remediation='Sanitize user input or use render_template with static templates',
                                detected_by='pattern'
                            )
                            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _track_tainted_variables(self, line_mapping: Dict[int, Dict[str, Any]], 
                                context: CodeContext) -> Dict[str, Dict[str, Any]]:
        """Track tainted variables across the code"""
        tainted_vars = {}
        
        # This is a placeholder for more sophisticated taint analysis
        # You could implement data flow analysis here
        
        return tainted_vars
    
    def _get_multiline_context(self, line_mapping: Dict[int, Dict[str, Any]], 
                              start_line: int, end_line: int) -> str:
        """Get code context for multiple lines"""
        context_lines = []
        for line_num in range(max(1, start_line - 1), min(len(line_mapping) + 1, end_line + 2)):
            if line_num in line_mapping:
                prefix = ">> " if line_num in [start_line, end_line] else "   "
                context_lines.append(f"{line_num:4d} | {prefix}{line_mapping[line_num]['content']}")
        return "\n".join(context_lines)
    
    async def _detect_with_ai_enhanced(self, code: str, context: CodeContext,
                                     line_mapping: Dict[int, Dict[str, Any]]) -> List[Vulnerability]:
        """AI detection with enhanced line number tracking"""
        
        await self._ensure_session()
        await self.rate_limiter.acquire()
        
        # Create numbered code for AI with clear line numbers
        numbered_lines = []
        for line_num, line_info in line_mapping.items():
            numbered_lines.append(f"{line_num:4d}: {line_info['content']}")
        numbered_code = "\n".join(numbered_lines)
        
        # Build enhanced prompt
        prompt = self._build_enhanced_security_prompt(numbered_code, context)
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        model_url = f"{self.base_url}{self.text_model}"
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 1500,
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
                    if isinstance(result, list) and len(result) > 0:
                        ai_response = result[0].get('generated_text', '')
                        return self._parse_ai_response_enhanced(ai_response, context, line_mapping)
                else:
                    error_text = await response.text()
                    logger.error(f"API error {response.status}: {error_text}")
                    
        except Exception as e:
            logger.error(f"Error calling Hugging Face API: {e}")
        
        return []
    
    def _build_enhanced_security_prompt(self, numbered_code: str, context: CodeContext) -> str:
        """Build enhanced prompt with line numbers for AI"""
        
        # Limit code length to avoid token limits
        max_code_length = 3000
        if len(numbered_code) > max_code_length:
            numbered_code = numbered_code[:max_code_length] + "\n... (truncated)"
        
        prompt = f"""You are a security expert analyzing {context.language.value} code for vulnerabilities.

IMPORTANT: Each line of code below starts with its line number (format: "   1: code").
You MUST use these exact line numbers in your response.

Analyze this numbered code for security vulnerabilities:

```{context.language.value}
{numbered_code}
```

For each vulnerability found, provide a JSON response with:
- type: The specific vulnerability type
- severity: Critical/High/Medium/Low
- line_number: The EXACT line number from the code above
- description: Detailed explanation of the vulnerability
- vulnerable_code: The exact line of code that contains the vulnerability
- attack_vector: How an attacker could exploit this

Respond with ONLY valid JSON:
{{
  "vulnerabilities": [
    {{
      "type": "SQL Injection",
      "severity": "High",
      "line_number": 42,
      "description": "User input 'username' is concatenated directly into SQL query without sanitization",
      "vulnerable_code": "query = 'SELECT * FROM users WHERE name = ' + username",
      "attack_vector": "Attacker can inject SQL commands through the username parameter"
    }}
  ]
}}

Focus on real security issues only. Be very specific about line numbers and code snippets."""
        
        return prompt
    
    def _parse_ai_response_enhanced(self, ai_response: str, context: CodeContext,
                                  line_mapping: Dict[int, Dict[str, Any]]) -> List[Vulnerability]:
        """Parse AI response with enhanced validation"""
        
        vulnerabilities = []
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
                
                for vuln_data in data.get('vulnerabilities', []):
                    line_num = vuln_data.get('line_number', 0)
                    
                    # Validate line number exists
                    if line_num not in line_mapping:
                        logger.warning(f"AI provided invalid line number: {line_num}")
                        continue
                    
                    # Extract the actual line content
                    actual_line = line_mapping[line_num]['content']
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        line_number=line_num,
                        line_content=actual_line.strip()
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
                        owasp_category=self._map_to_owasp(vuln_data.get('type', '')),
                        cwe_id=self._map_to_cwe(vuln_data.get('type', '')),
                        location=location,
                        vulnerable_code=vuln_data.get('vulnerable_code', actual_line),
                        attack_vector=vuln_data.get('attack_vector', ''),
                        remediation=self._get_remediation(vuln_data.get('type', '')),
                        detected_by='ai'
                    )
                    
                    vulnerabilities.append(vulnerability)
                    logger.debug(f"AI found {vulnerability.type} at line {line_num}")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing AI response as JSON: {e}")
            logger.debug(f"AI response: {ai_response[:500]}...")
        except Exception as e:
            logger.error(f"Error processing AI response: {e}")
        
        return vulnerabilities
    
    def _get_enhanced_vulnerability_patterns(self, language: str) -> List[Dict[str, Any]]:
        """Get enhanced vulnerability patterns with better metadata"""
        
        patterns = {
            'python': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(?:execute|query|executemany)\s*\(\s*[^)]*(?:\+|%|\.format\()',
                    'severity': Severity.HIGH,
                    'confidence': 0.9,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'User input concatenated or formatted into SQL query without parameterization',
                    'attack_vector': 'Attacker can modify SQL query structure to access or modify unauthorized data',
                    'remediation': 'Use parameterized queries with placeholders (e.g., cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)))'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'(?:os\.system|subprocess\.(?:call|run|Popen)|exec|eval)\s*\([^)]*(?:\+|%|\.format\()',
                    'severity': Severity.HIGH,
                    'confidence': 0.9,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'User input passed to system command execution without proper sanitization',
                    'attack_vector': 'Attacker can execute arbitrary system commands with application privileges',
                    'remediation': 'Use subprocess with shell=False and pass arguments as a list, validate/sanitize all inputs'
                },
                {
                    'name': 'Hardcoded Secret',
                    'pattern': r'(?:password|passwd|pwd|secret[_-]?key|api[_-]?key|apikey|token|auth[_-]?token)\s*=\s*["\'][^"\']{8,}["\']',
                    'severity': Severity.HIGH,
                    'confidence': 0.8,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Sensitive credential hardcoded in source code',
                    'attack_vector': 'Anyone with access to source code can obtain credentials',
                    'remediation': 'Use environment variables or secure configuration management systems'
                },
                {
                    'name': 'Insecure Deserialization',
                    'pattern': r'(?:pickle\.loads?|yaml\.load|marshal\.loads?)\s*\(',
                    'severity': Severity.HIGH,
                    'confidence': 0.85,
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'cwe': 'CWE-502',
                    'description': 'Unsafe deserialization of untrusted data',
                    'attack_vector': 'Attacker can execute arbitrary code through malicious serialized objects',
                    'remediation': 'Use safe alternatives like json.loads() or yaml.safe_load()'
                },
                {
                    'name': 'Path Traversal',
                    'pattern': r'(?:open|file|os\.path\.join)\s*\([^)]*(?:request\.|input\(|argv|\.get\()',
                    'severity': Severity.MEDIUM,
                    'confidence': 0.75,
                    'owasp': 'A01:2021 - Broken Access Control',
                    'cwe': 'CWE-22',
                    'description': 'User-controlled path used in file operations',
                    'attack_vector': 'Attacker can access files outside intended directory using ../ sequences',
                    'remediation': 'Validate and sanitize file paths, use os.path.basename() and check against whitelist'
                },
                {
                    'name': 'Weak Cryptography',
                    'pattern': r'(?:md5|sha1|MD5|SHA1|DES|RC4)\s*\(',
                    'severity': Severity.MEDIUM,
                    'confidence': 0.85,
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'cwe': 'CWE-327',
                    'description': 'Use of weak or deprecated cryptographic algorithm',
                    'attack_vector': 'Weak algorithms can be broken with modern computing power',
                    'remediation': 'Use strong algorithms like SHA-256, SHA-3, or AES with proper key sizes'
                },
                {
                    'name': 'Flask Debug Mode',
                    'pattern': r'app\.run\s*\([^)]*debug\s*=\s*True',
                    'severity': Severity.HIGH,
                    'confidence': 0.95,
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'cwe': 'CWE-489',
                    'description': 'Flask application running in debug mode',
                    'attack_vector': 'Debug mode exposes sensitive information and allows code execution',
                    'remediation': 'Disable debug mode in production (debug=False)'
                }
            ],
            'go': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(?:Query|Exec|QueryRow)\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'confidence': 0.9,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'String concatenation in SQL query',
                    'attack_vector': 'SQL injection through unsanitized user input',
                    'remediation': 'Use prepared statements with placeholders'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'exec\.Command\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'confidence': 0.9,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection through string concatenation',
                    'attack_vector': 'Arbitrary command execution',
                    'remediation': 'Use exec.Command with separate arguments'
                }
            ],
            'java': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'(?:createStatement|prepareStatement)\s*\(\s*\).*?(?:execute|executeQuery|executeUpdate)\s*\([^)]*\+',
                    'severity': Severity.HIGH,
                    'confidence': 0.9,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection through string concatenation',
                    'attack_vector': 'Malicious SQL injection',
                    'remediation': 'Use PreparedStatement with parameters'
                }
            ],
            'csharp': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'SqlCommand\s*\([^)]*\+[^)]*\)',
                    'severity': Severity.HIGH,
                    'confidence': 0.9,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability',
                    'attack_vector': 'SQL injection attack',
                    'remediation': 'Use parameterized queries'
                }
            ]
        }
        
        return patterns.get(language, [])
    
    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP category"""
        
        mapping = {
            'injection': 'A03:2021 - Injection',
            'sql': 'A03:2021 - Injection',
            'command': 'A03:2021 - Injection',
            'template': 'A03:2021 - Injection',
            'ssti': 'A03:2021 - Injection',
            'crypto': 'A02:2021 - Cryptographic Failures',
            'access': 'A01:2021 - Broken Access Control',
            'auth': 'A07:2021 - Identification and Authentication Failures',
            'deserialization': 'A08:2021 - Software and Data Integrity Failures',
            'xxe': 'A05:2021 - Security Misconfiguration',
            'path': 'A01:2021 - Broken Access Control',
            'traversal': 'A01:2021 - Broken Access Control'
        }
        
        vuln_lower = vuln_type.lower()
        for key, value in mapping.items():
            if key in vuln_lower:
                return value
        
        return 'A00:2021 - Unknown Category'
    
    def _map_to_cwe(self, vuln_type: str) -> Optional[str]:
        """Map vulnerability type to CWE ID"""
        
        mapping = {
            'sql injection': 'CWE-89',
            'command injection': 'CWE-78',
            'ssti': 'CWE-94',
            'template injection': 'CWE-94',
            'path traversal': 'CWE-22',
            'hardcoded': 'CWE-798',
            'weak crypto': 'CWE-327',
            'deserialization': 'CWE-502'
        }
        
        vuln_lower = vuln_type.lower()
        for key, value in mapping.items():
            if key in vuln_lower:
                return value
        
        return None
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get detailed remediation advice for vulnerability type"""
        
        remediations = {
            'SQL Injection': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
            'Command Injection': 'Validate and sanitize all user input. Use subprocess with shell=False and pass arguments as a list.',
            'Server-Side Template Injection': 'Use static templates with proper context variables. Avoid render_template_string with user input.',
            'Path Traversal': 'Validate file paths against a whitelist. Use os.path.basename() and ensure paths stay within allowed directories.',
            'Hardcoded Secret': 'Store secrets in environment variables or secure configuration management systems. Never commit secrets to version control.',
            'Insecure Deserialization': 'Use safe serialization formats like JSON. If using pickle/yaml, ensure data comes from trusted sources only.',
            'Weak Cryptography': 'Use strong, modern cryptographic algorithms. Replace MD5/SHA1 with SHA-256 or SHA-3.',
            'SSTI': 'Use render_template with separate template files instead of render_template_string with user input.'
        }
        
        for key, value in remediations.items():
            if key.lower() in vuln_type.lower():
                return value
        
        return 'Follow security best practices for this vulnerability type'
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities, keeping the highest confidence ones"""
        
        # Group by type and line number
        grouped = {}
        for vuln in vulnerabilities:
            key = (vuln.type, vuln.location.line_number if vuln.location else 0)
            
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(vuln)
        
        # Keep only the highest confidence vulnerability from each group
        deduplicated = []
        for vulns in grouped.values():
            # Sort by confidence (descending) and detected_by (ai preferred over pattern)
            vulns.sort(key=lambda v: (v.confidence, v.detected_by == 'ai'), reverse=True)
            deduplicated.append(vulns[0])
        
        # Sort by line number for consistent output
        deduplicated.sort(key=lambda v: v.location.line_number if v.location else 0)
        
        return deduplicated
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        
        # Enhanced pattern-based fixes with examples
        fixes = {
            'SQL Injection': '''# Use parameterized query:
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
# Or with named parameters:
cursor.execute("SELECT * FROM users WHERE username = :username", {"username": username})''',
            
            'Command Injection': '''# Use subprocess without shell:
import subprocess
import shlex
# Safe approach 1: Pass arguments as list
subprocess.run(["echo", user_input], shell=False)
# Safe approach 2: If you must use shell, quote the input
subprocess.run(f"echo {shlex.quote(user_input)}", shell=True)''',
            
            'Server-Side Template Injection': '''# Use static template file:
from flask import render_template
# Create templates/hello.html with: <h1>Hello {{ username }}!</h1>
return render_template('hello.html', username=username)''',
            
            'Path Traversal': '''# Validate and sanitize path:
import os
base_dir = '/safe/directory'
requested_file = os.path.basename(user_input)  # Remove directory components
safe_path = os.path.join(base_dir, requested_file)
# Verify the path is within base_dir
if not safe_path.startswith(base_dir):
    raise ValueError("Invalid path")''',
            
            'Hardcoded Secret': '''# Use environment variables:
import os
api_key = os.environ.get('API_KEY')
if not api_key:
    raise ValueError("API_KEY environment variable not set")
# Or use python-dotenv:
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv('API_KEY')''',
            
            'Insecure Deserialization': '''# Use JSON instead of pickle:
import json
# Instead of: data = pickle.loads(user_input)
data = json.loads(user_input)
# For YAML, use safe_load:
import yaml
data = yaml.safe_load(user_input)''',
            
            'Weak Cryptography': '''# Use strong algorithms:
import hashlib
# Instead of: hashlib.md5(data).hexdigest()
hash_value = hashlib.sha256(data.encode()).hexdigest()
# For passwords, use bcrypt or argon2:
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)'''
        }
        
        # Try to find a matching fix
        for vuln_type, fix in fixes.items():
            if vuln_type.lower() in vulnerability.type.lower():
                return fix
        
        # If no specific fix found and AI is available, try to generate one
        if not self.pattern_only and self.api_key and vulnerability.vulnerable_code:
            try:
                await self._ensure_session()
                await self.rate_limiter.acquire()
                
                prompt = f"""Fix this {vulnerability.type} vulnerability:

Vulnerable code:
{vulnerability.vulnerable_code}

Provide a secure code fix with explanation:"""

                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                model_url = f"{self.base_url}{self.text_model}"
                payload = {
                    "inputs": prompt,
                    "parameters": {
                        "max_new_tokens": 300,
                        "temperature": 0.1
                    }
                }
                
                async with self.session.post(model_url, headers=headers, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        if isinstance(result, list) and len(result) > 0:
                            return result[0].get('generated_text', 'Unable to generate fix.')
                            
            except Exception as e:
                logger.error(f"Error generating fix: {e}")
        
        return 'Follow security best practices for this vulnerability type.'
    
    def get_token_count(self, text: str) -> int:
        """Estimate token count"""
        # Rough estimate: ~4 characters per token
        return len(text) // 4
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
    
    async def close(self):
        """Close the aiohttp session"""
        await self.cleanup()