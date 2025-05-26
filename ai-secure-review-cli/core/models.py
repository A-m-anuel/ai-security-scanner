from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Language(Enum):
    PYTHON = "python"
    GO = "go"
    JAVA = "java"
    CSHARP = "csharp"

@dataclass
class CodeLocation:
    """Represents a location in source code"""
    file_path: str
    line_number: int
    column: Optional[int] = None
    line_content: Optional[str] = None
    
    def __str__(self):
        return f"{self.file_path}:{self.line_number}"

@dataclass
class Vulnerability:
    """Represents a security vulnerability found in code"""
    id: str
    type: str
    title: str
    description: str
    severity: Severity
    confidence: float  # 0.0 to 1.0
    owasp_category: str
    cwe_id: Optional[str] = None
    location: Optional[CodeLocation] = None
    vulnerable_code: Optional[str] = None
    attack_vector: Optional[str] = None
    business_impact: Optional[str] = None
    remediation: Optional[str] = None
    fix_suggestion: Optional[str] = None
    references: List[str] = None
    detected_by: str = "ai"  # "ai" or "static"
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'type': self.type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'owasp_category': self.owasp_category,
            'cwe_id': self.cwe_id,
            'location': {
                'file_path': self.location.file_path,
                'line_number': self.location.line_number,
                'column': self.location.column,
                'line_content': self.location.line_content
            } if self.location else None,
            'vulnerable_code': self.vulnerable_code,
            'attack_vector': self.attack_vector,
            'business_impact': self.business_impact,
            'remediation': self.remediation,
            'fix_suggestion': self.fix_suggestion,
            'references': self.references,
            'detected_by': self.detected_by
        }

@dataclass
class CodeContext:
    """Represents context information about a code snippet"""
    file_path: str
    language: Language
    imports: List[str]
    functions: List[str]
    classes: List[str]
    dependencies: List[str]
    framework: Optional[str] = None
    database_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'file_path': self.file_path,
            'language': self.language.value,
            'imports': self.imports,
            'functions': self.functions,
            'classes': self.classes,
            'dependencies': self.dependencies,
            'framework': self.framework,
            'database_type': self.database_type
        }

@dataclass
class AnalysisResult:
    """Represents the result of analyzing a code file or snippet"""
    file_path: str
    language: Language
    vulnerabilities: List[Vulnerability]
    analysis_time: float
    token_usage: int
    ai_model_used: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL])
    
    @property
    def high_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == Severity.HIGH])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'file_path': self.file_path,
            'language': self.language.value,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'analysis_time': self.analysis_time,
            'token_usage': self.token_usage,
            'ai_model_used': self.ai_model_used,
            'timestamp': self.timestamp.isoformat(),
            'summary': {
                'total_vulnerabilities': self.vulnerability_count,
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM]),
                'low': len([v for v in self.vulnerabilities if v.severity == Severity.LOW])
            }
        }

@dataclass
class ScanResult:
    """Represents the result of scanning an entire codebase"""
    project_path: str
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    file_results: List[AnalysisResult] = None
    total_files_scanned: int = 0
    total_vulnerabilities: int = 0
    ai_provider: Optional[str] = None
    
    def __post_init__(self):
        if self.file_results is None:
            self.file_results = []
    
    @property
    def scan_duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all file results"""
        all_vulns = []
        for result in self.file_results:
            all_vulns.extend(result.vulnerabilities)
        return all_vulns
    
    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity"""
        return [v for v in self.all_vulnerabilities if v.severity == severity]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics"""
        all_vulns = self.all_vulnerabilities
        return {
            'scan_id': self.scan_id,
            'project_path': self.project_path,
            'duration': self.scan_duration,
            'files_scanned': self.total_files_scanned,
            'total_vulnerabilities': len(all_vulns),
            'severity_breakdown': {
                'critical': len([v for v in all_vulns if v.severity == Severity.CRITICAL]),
                'high': len([v for v in all_vulns if v.severity == Severity.HIGH]),
                'medium': len([v for v in all_vulns if v.severity == Severity.MEDIUM]),
                'low': len([v for v in all_vulns if v.severity == Severity.LOW]),
                'info': len([v for v in all_vulns if v.severity == Severity.INFO])
            },
            'owasp_breakdown': self._get_owasp_breakdown(),
            'ai_provider': self.ai_provider
        }
    
    def _get_owasp_breakdown(self) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by OWASP category"""
        owasp_count = {}
        for vuln in self.all_vulnerabilities:
            category = vuln.owasp_category
            owasp_count[category] = owasp_count.get(category, 0) + 1
        return owasp_count
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'summary': self.get_summary(),
            'file_results': [result.to_dict() for result in self.file_results]
        }