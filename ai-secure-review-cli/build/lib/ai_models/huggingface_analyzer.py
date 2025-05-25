# ai_models/huggingface_analyzer.py
import asyncio
import aiohttp
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from .model_interface import AIModelInterface
from core.models import Vulnerability, CodeContext, Severity, CodeLocation
from utils.rate_limiter import RateLimiter

class HuggingFaceAnalyzer(AIModelInterface):
    """Hugging Face API-based code security analyzer"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Hugging Face configuration
        self.api_key = config['api_key']
        self.base_url = config.get('base_url', 'https://api-inference.huggingface.co/models/')
        self.model_name = config.get('model', 'microsoft/DialoGPT-large')  # Default model
        
        # Rate limiter for free tier
        self.rate_limiter = RateLimiter(
            max_calls=config.get('rate_limit', 30),  # Conservative for free tier
            time_window=60  # per minute
        )
        
        # Available models for different tasks
        self.models = {
            'code_analysis': config.get('code_model', 'microsoft/CodeBERT-base'),
            'text_generation': config.get('text_model', 'microsoft/DialoGPT-large'),
            'classification': config.get('classification_model', 'microsoft/codebert-base'),
        }
    
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities using Hugging Face models"""
        
        # Wait for rate limit
        await self.rate_limiter.acquire()
        
        try:
            # Use a combination of pattern detection and AI analysis
            vulnerabilities = []
            
            # First, use pattern-based detection for common issues
            pattern_vulns = self._detect_pattern_vulnerabilities(code, context)
            vulnerabilities.extend(pattern_vulns)
            
            # Then enhance with AI analysis for context and severity
            if vulnerabilities:
                enhanced_vulns = await self._enhance_with_ai(vulnerabilities, code, context)
                return enhanced_vulns
            else:
                # If no pattern matches, try AI-based analysis
                ai_vulns = await self._ai_vulnerability_detection(code, context)
                return ai_vulns
            
        except Exception as e:
            print(f"Error analyzing code with Hugging Face: {e}")
            return []
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        
        await self.rate_limiter.acquire()
        
        try:
            # Create a fix generation prompt
            prompt = self._build_fix_prompt(vulnerability, code)
            
            # Use text generation model
            response = await self._call_huggingface_api(
                model=self.models['text_generation'],
                inputs=prompt,
                parameters={
                    "max_length": 200,
                    "temperature": 0.3,
                    "do_sample": True
                }
            )
            
            if response and isinstance(response, list) and len(response) > 0:
                generated_text = response[0].get('generated_text', '')
                # Extract the fix from the generated text
                fix = self._extract_fix_from_response(generated_text, prompt)
                return fix
            
            return self._get_default_fix_suggestion(vulnerability)
            
        except Exception as e:
            print(f"Error generating fix with Hugging Face: {e}")
            return self._get_default_fix_suggestion(vulnerability)
    
    def get_token_count(self, text: str) -> int:
        """Estimate token count for text (rough approximation)"""
        # Rough estimation: ~4 characters per token for English
        return len(text) // 4
    
    async def _call_huggingface_api(self, model: str, inputs: str, parameters: Dict = None) -> Any:
        """Make API call to Hugging Face"""
        
        url = f"{self.base_url}{model}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "inputs": inputs
        }
        
        if parameters:
            payload["parameters"] = parameters
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    print(f"Hugging Face API error: {response.status} - {error_text}")
                    return None
    
    def _detect_pattern_vulnerabilities(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Detect vulnerabilities using pattern matching"""
        
        vulnerabilities = []
        language = context.language.value
        
        # Get language-specific patterns
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
                {
                    'name': 'SQL Injection',
                    'pattern': r'(cursor\.execute|execute)\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'Potential SQL injection vulnerability from string concatenation in query'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'os\.system\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection vulnerability through os.system()'
                },
                {
                    'name': 'Hardcoded Password',
                    'pattern': r'password\s*=\s*["\'][^"\']{8,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded password detected'
                },
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
                    'pattern': r'Query\s*\(\s*["`].*\+.*["`]',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'Potential SQL injection from string concatenation'
                },
                {
                    'name': 'Command Injection',
                    'pattern': r'exec\.Command\s*\(\s*["`].*\+.*["`]',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-78',
                    'description': 'Command injection through exec.Command'
                },
                {
                    'name': 'Hardcoded Credentials',
                    'pattern': r'(password|key|secret)\s*:?=\s*["`][^"`]{8,}["`]',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded credentials detected'
                }
            ],
            'java': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'executeQuery\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection through string concatenation'
                },
                {
                    'name': 'Hardcoded Password',
                    'pattern': r'password\s*=\s*["\'][^"\']{8,}["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded password found'
                }
            ],
            'csharp': [
                {
                    'name': 'SQL Injection',
                    'pattern': r'ExecuteQuery\s*\(\s*["\'].*\+.*["\']',
                    'severity': Severity.HIGH,
                    'owasp': 'A03:2021 - Injection',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability detected'
                },
                {
                    'name': 'Hardcoded Connection String',
                    'pattern': r'connectionString\s*=\s*["\'][^"\']*password[^"\']*["\']',
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
        import re
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
            confidence=0.8,  # Pattern-based detection has good confidence
            owasp_category=pattern_info['owasp'],
            cwe_id=pattern_info['cwe'],
            location=location,
            vulnerable_code=line.strip(),
            remediation=self._get_remediation_advice(pattern_info['name']),
            detected_by='pattern+ai'
        )
    
    async def _enhance_with_ai(self, vulnerabilities: List[Vulnerability], 
                              code: str, context: CodeContext) -> List[Vulnerability]:
        """Enhance pattern-detected vulnerabilities with AI analysis"""
        
        for vuln in vulnerabilities:
            try:
                # Generate more detailed description
                enhanced_desc = await self._get_ai_description(vuln, code, context)
                if enhanced_desc:
                    vuln.description = enhanced_desc
                
                # Generate business impact
                business_impact = await self._get_business_impact(vuln, context)
                if business_impact:
                    vuln.business_impact = business_impact
                
            except Exception as e:
                print(f"Error enhancing vulnerability with AI: {e}")
                continue
        
        return vulnerabilities
    
    async def _ai_vulnerability_detection(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """AI-based vulnerability detection as fallback"""
        
        try:
            # Create a prompt for vulnerability detection
            prompt = f"""
Analyze this {context.language.value} code for security vulnerabilities:

{code[:1000]}  # Limit code length for API

List any security issues found.
"""
            
            response = await self._call_huggingface_api(
                model=self.models['text_generation'],
                inputs=prompt,
                parameters={"max_length": 150, "temperature": 0.2}
            )
            
            if response:
                # Parse AI response and create vulnerabilities
                return self._parse_ai_vulnerability_response(response, context)
            
        except Exception as e:
            print(f"Error in AI vulnerability detection: {e}")
        
        return []
    
    async def _get_ai_description(self, vuln: Vulnerability, code: str, context: CodeContext) -> Optional[str]:
        """Get AI-enhanced description for vulnerability"""
        
        prompt = f"Explain this {vuln.type} vulnerability in {context.language.value}: {vuln.vulnerable_code}"
        
        try:
            response = await self._call_huggingface_api(
                model=self.models['text_generation'],
                inputs=prompt,
                parameters={"max_length": 100, "temperature": 0.3}
            )
            
            if response and isinstance(response, list) and len(response) > 0:
                return response[0].get('generated_text', '').replace(prompt, '').strip()
        except Exception:
            pass
        
        return None
    
    async def _get_business_impact(self, vuln: Vulnerability, context: CodeContext) -> Optional[str]:
        """Get business impact assessment"""
        
        impact_templates = {
            'SQL Injection': 'Could lead to unauthorized database access, data theft, or data manipulation',
            'Command Injection': 'May allow attackers to execute arbitrary commands on the server',
            'Hardcoded Password': 'Exposes credentials that could be used for unauthorized access',
            'Insecure Deserialization': 'Could allow remote code execution or application compromise',
            'Weak Cryptography': 'May allow attackers to compromise encrypted data'
        }
        
        return impact_templates.get(vuln.type, 'Could impact application security and data integrity')
    
    def _build_fix_prompt(self, vulnerability: Vulnerability, code: str) -> str:
        """Build prompt for fix generation"""
        
        return f"""
Fix this security issue:
Problem: {vulnerability.type}
Code: {vulnerability.vulnerable_code}
Solution:"""
    
    def _extract_fix_from_response(self, generated_text: str, prompt: str) -> str:
        """Extract fix suggestion from AI response"""
        
        # Remove the original prompt from response
        fix = generated_text.replace(prompt, '').strip()
        
        # Clean up the response
        if fix and len(fix) > 10:
            return fix
        
        return "Use parameterized queries and input validation"
    
    def _get_default_fix_suggestion(self, vulnerability: Vulnerability) -> str:
        """Get default fix suggestion for vulnerability type"""
        
        default_fixes = {
            'SQL Injection': 'Use parameterized queries or prepared statements instead of string concatenation',
            'Command Injection': 'Validate and sanitize all user input before using in system commands',
            'Hardcoded Password': 'Store credentials in environment variables or secure configuration files',
            'Insecure Deserialization': 'Use safe serialization formats like JSON, avoid pickle for untrusted data',
            'Weak Cryptography': 'Use strong cryptographic algorithms like SHA-256 or bcrypt for password hashing'
        }
        
        return default_fixes.get(vulnerability.type, 'Review and fix the identified security issue')
    
    def _get_remediation_advice(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        
        remediation_guide = {
            'SQL Injection': 'Use parameterized queries, input validation, and least privilege database access',
            'Command Injection': 'Sanitize user input, use safe APIs, avoid shell execution when possible',
            'Hardcoded Password': 'Use environment variables, secure vaults, or configuration management',
            'Insecure Deserialization': 'Validate serialized data, use safe formats, implement integrity checks',
            'Weak Cryptography': 'Use industry-standard algorithms, proper key management, and regular updates'
        }
        
        return remediation_guide.get(vuln_type, 'Follow security best practices for this vulnerability type')
    
    def _parse_ai_vulnerability_response(self, response: Any, context: CodeContext) -> List[Vulnerability]:
        """Parse AI response into vulnerability objects"""
        
        vulnerabilities = []
        
        try:
            if isinstance(response, list) and len(response) > 0:
                text = response[0].get('generated_text', '')
                
                # Simple parsing - look for security-related keywords
                security_keywords = ['injection', 'xss', 'csrf', 'sql', 'command', 'password', 'crypto']
                
                if any(keyword in text.lower() for keyword in security_keywords):
                    # Create a generic vulnerability
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        type='Security Issue',
                        title='Potential Security Issue Detected',
                        description=text[:200],  # Limit description length
                        severity=Severity.MEDIUM,
                        confidence=0.6,  # Lower confidence for AI-only detection
                        owasp_category='A04:2021 - Insecure Design',
                        location=CodeLocation(
                            file_path=context.file_path,
                            line_number=1
                        ),
                        detected_by='ai'
                    )
                    vulnerabilities.append(vuln)
        except Exception as e:
            print(f"Error parsing AI response: {e}")
        
        return vulnerabilities

