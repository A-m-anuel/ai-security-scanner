
# ai_models/openai_analyzer.py
import openai
import asyncio
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import tiktoken

from .model_interface import AIModelInterface
from core.models import Vulnerability, CodeContext, Severity, CodeLocation
from utils.rate_limiter import RateLimiter

class OpenAIAnalyzer(AIModelInterface):
    """OpenAI GPT-based code security analyzer"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Initialize OpenAI client
        openai.api_key = config['api_key']
        self.client = openai.AsyncOpenAI(api_key=config['api_key'])
        
        # Rate limiter
        self.rate_limiter = RateLimiter(
            max_calls=config.get('rate_limit', 10),
            time_window=60  # per minute
        )
        
        # Token encoder for counting
        try:
            self.encoding = tiktoken.encoding_for_model(self.model_name)
        except KeyError:
            self.encoding = tiktoken.get_encoding("cl100k_base")  # Default encoding
    
    async def analyze_code(self, code: str, context: CodeContext) -> List[Vulnerability]:
        """Analyze code for security vulnerabilities using OpenAI"""
        
        # Wait for rate limit
        await self.rate_limiter.acquire()
        
        # Build the analysis prompt
        prompt = self._build_security_analysis_prompt(code, context)
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                response_format={"type": "json_object"}
            )
            
            # Parse the response
            response_text = response.choices[0].message.content
            vulnerabilities = self._parse_ai_response(response_text, context)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error analyzing code with OpenAI: {e}")
            return []
    
    async def generate_fix(self, vulnerability: Vulnerability, code: str) -> str:
        """Generate fix suggestion for a vulnerability"""
        
        await self.rate_limiter.acquire()
        
        prompt = self._build_fix_generation_prompt(vulnerability, code)
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a security expert providing code fixes."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"Error generating fix with OpenAI: {e}")
            return "Unable to generate fix suggestion."
    
    def get_token_count(self, text: str) -> int:
        """Estimate token count for text"""
        return len(self.encoding.encode(text))
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for security analysis"""
        return """You are a senior security engineer and code reviewer with expertise in identifying security vulnerabilities across multiple programming languages.

Your task is to analyze code for security issues and map them to the OWASP Top 10 2021. Focus on:

1. Real security vulnerabilities, not style issues
2. Specific line numbers where issues occur
3. Clear explanations of attack vectors
4. Practical remediation advice

Always respond with valid JSON format containing a "vulnerabilities" array."""
    
    def _build_security_analysis_prompt(self, code: str, context: CodeContext) -> str:
        """Build the security analysis prompt"""
        
        language_specific_guidance = self._get_language_specific_guidance(context.language.value)
        
        prompt = f"""Analyze this {context.language.value} code for security vulnerabilities:

CODE:
```{context.language.value}
{code}
```

CONTEXT:
- File: {context.file_path}
- Imports: {', '.join(context.imports[:10])}  
- Functions: {', '.join(context.functions[:5])}
- Framework: {context.framework or 'Unknown'}
- Database: {context.database_type or 'Unknown'}

{language_specific_guidance}

ANALYSIS REQUIREMENTS:
1. Identify specific security vulnerabilities (not code quality issues)
2. Map each finding to OWASP Top 10 2021 categories
3. Provide exact line numbers where issues occur
4. Assign appropriate severity levels
5. Include confidence scores (0.0-1.0)
6. Explain attack vectors and business impact
7. Provide specific remediation guidance

OUTPUT FORMAT (JSON):
{{
  "vulnerabilities": [
    {{
      "type": "SQL Injection",
      "title": "Unsanitized database query",
      "description": "User input directly concatenated into SQL query",
      "severity": "High",
      "confidence": 0.95,
      "owasp_category": "A03:2021 - Injection",
      "cwe_id": "CWE-89",
      "line_number": 42,
      "vulnerable_code": "SELECT * FROM users WHERE id = " + user_id,
      "attack_vector": "Attacker can inject malicious SQL code through user_id parameter",
      "business_impact": "Complete database compromise, data theft, data manipulation",
      "remediation": "Use parameterized queries or prepared statements"
    }}
  ]
}}"""

        return prompt
    
    def _get_language_specific_guidance(self, language: str) -> str:
        """Get language-specific security guidance"""
        
        guidance = {
            'python': """
PYTHON-SPECIFIC VULNERABILITIES TO CHECK:
- SQL Injection: Raw string concatenation in database queries
- Command Injection: os.system(), subprocess with shell=True
- Deserialization: pickle.loads(), yaml.load() without safe_load
- Path Traversal: open() with user input, os.path.join() misuse
- XSS: Django/Flask template rendering without escaping
- CSRF: Missing CSRF tokens in forms
- Hardcoded Secrets: API keys, passwords in code
- Weak Crypto: MD5/SHA1 for passwords, hardcoded keys
""",
            'go': """
GO-SPECIFIC VULNERABILITIES TO CHECK:
- SQL Injection: String concatenation in database/sql queries
- Command Injection: exec.Command with user input
- Path Traversal: filepath.Join() misuse, os.Open() with user input
- Race Conditions: Shared variables without proper locking
- Crypto Issues: Weak random number generation, improper TLS config
- Input Validation: Missing validation in HTTP handlers
""",
            'java': """
JAVA-SPECIFIC VULNERABILITIES TO CHECK:
- SQL Injection: Statement vs PreparedStatement usage
- XXE: XML parsing without disabling external entities
- Deserialization: ObjectInputStream with untrusted data
- Path Traversal: File operations with user input
- LDAP Injection: String concatenation in LDAP queries
- Weak Crypto: DES, MD5, hardcoded keys
""",
            'csharp': """
C#-SPECIFIC VULNERABILITIES TO CHECK:
- SQL Injection: String concatenation in SQL queries
- XXE: XmlDocument without secure settings
- Path Traversal: Path.Combine() with user input
- Deserialization: BinaryFormatter, JSON.NET TypeNameHandling
- LDAP Injection: DirectorySearcher with user input
- Crypto Issues: MD5, SHA1, hardcoded keys
"""
        }
        
        return guidance.get(language, "Focus on common vulnerability patterns for this language.")
    
    def _build_fix_generation_prompt(self, vulnerability: Vulnerability, code: str) -> str:
        """Build prompt for generating fix suggestions"""
        
        return f"""Generate a secure code fix for this vulnerability:

VULNERABILITY: {vulnerability.type}
DESCRIPTION: {vulnerability.description}
SEVERITY: {vulnerability.severity.value}

VULNERABLE CODE:
```
{vulnerability.vulnerable_code or code[:500]}
```

Requirements:
1. Provide the corrected code
2. Explain what was changed and why
3. Include additional security measures if applicable
4. Maintain the original functionality
5. Follow security best practices

Format your response as:
FIXED CODE:
```
[corrected code here]
```

EXPLANATION:
[explanation of changes]
"""
    
    def _parse_ai_response(self, response_text: str, context: CodeContext) -> List[Vulnerability]:
        """Parse AI response into Vulnerability objects"""
        
        try:
            data = json.loads(response_text)
            vulnerabilities = []
            
            for vuln_data in data.get('vulnerabilities', []):
                # Create location object
                location = None
                if 'line_number' in vuln_data:
                    location = CodeLocation(
                        file_path=context.file_path,
                        line_number=vuln_data['line_number'],
                        line_content=vuln_data.get('vulnerable_code', '')
                    )
                
                # Parse severity
                severity_str = vuln_data.get('severity', 'Medium')
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.MEDIUM
                
                # Create vulnerability object
                vulnerability = Vulnerability(
                    id=str(uuid.uuid4()),
                    type=vuln_data.get('type', 'Unknown'),
                    title=vuln_data.get('title', vuln_data.get('type', 'Security Issue')),
                    description=vuln_data.get('description', ''),
                    severity=severity,
                    confidence=float(vuln_data.get('confidence', 0.8)),
                    owasp_category=vuln_data.get('owasp_category', 'Unknown'),
                    cwe_id=vuln_data.get('cwe_id'),
                    location=location,
                    vulnerable_code=vuln_data.get('vulnerable_code'),
                    attack_vector=vuln_data.get('attack_vector'),
                    business_impact=vuln_data.get('business_impact'),
                    remediation=vuln_data.get('remediation'),
                    detected_by='ai'
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except json.JSONDecodeError as e:
            print(f"Error parsing AI response: {e}")
            print(f"Response: {response_text[:200]}...")
            return []
        except Exception as e:
            print(f"Error creating vulnerabilities: {e}")
            return []