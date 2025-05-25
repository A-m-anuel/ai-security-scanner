# setup_project_fixed.py - Fixed version without Unicode issues
import os
from pathlib import Path

def create_init_files():
    """Create __init__.py files in all Python packages"""
    
    directories = [
        "core",
        "ai_models", 
        "parsers",
        "utils",
        "reports"
    ]
    
    for directory in directories:
        init_file = Path(directory) / "__init__.py"
        if not init_file.exists():
            init_file.touch()
            print(f"Created {init_file}")

def create_missing_files():
    """Create any missing essential files"""
    
    # Create reports/ai_report_generator.py if missing
    report_file = Path("reports") / "ai_report_generator.py"
    if not report_file.exists():
        report_content = '''# reports/ai_report_generator.py
import json
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.models import ScanResult, Vulnerability, Severity

class AIReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.owasp_categories = config.get('owasp_categories', {})
    
    def generate_report(self, scan_result: ScanResult, format_type: str) -> str:
        """Generate report in specified format"""
        
        if format_type == 'json':
            return self._generate_json_report(scan_result)
        elif format_type == 'html':
            return self._generate_html_report(scan_result)
        elif format_type == 'markdown':
            return self._generate_markdown_report(scan_result)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
    
    def print_console_report(self, scan_result: ScanResult, console: Console):
        """Print formatted report to console"""
        
        summary = scan_result.get_summary()
        
        summary_text = f"""[bold blue]Scan Summary[/bold blue]
Project: {summary['project_path']}
Duration: {summary['duration']:.2f} seconds
Files Scanned: {summary['files_scanned']}
AI Provider: {summary['ai_provider']}

[bold red]Critical: {summary['severity_breakdown']['critical']}[/bold red]
[bold yellow]High: {summary['severity_breakdown']['high']}[/bold yellow]
[bold blue]Medium: {summary['severity_breakdown']['medium']}[/bold blue]
[bold green]Low: {summary['severity_breakdown']['low']}[/bold green]
Info: {summary['severity_breakdown']['info']}

Total Vulnerabilities: {summary['total_vulnerabilities']}"""
        
        console.print(Panel(summary_text, title="Security Scan Results"))
        
        # Show vulnerabilities if found
        vulnerabilities = scan_result.all_vulnerabilities
        if not vulnerabilities:
            console.print("[green]No vulnerabilities found![/green]")
            return
        
        # Create table for vulnerabilities
        table = Table(title="Vulnerabilities Found")
        table.add_column("File", style="cyan")
        table.add_column("Line", justify="right", style="magenta")
        table.add_column("Severity", style="red")
        table.add_column("Issue", style="white")
        table.add_column("OWASP", style="green")
        
        for vuln in vulnerabilities:
            location = vuln.location
            file_path = Path(location.file_path).name if location else "Unknown"
            line_num = str(location.line_number) if location else "?"
            
            table.add_row(
                file_path,
                line_num,
                vuln.severity.value,
                vuln.title,
                vuln.owasp_category.split(':')[0] if ':' in vuln.owasp_category else vuln.owasp_category
            )
        
        console.print(table)
    
    def _generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate JSON report"""
        return json.dumps(scan_result.to_dict(), indent=2, default=str)
    
    def _generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate HTML report"""
        
        summary = scan_result.get_summary()
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 6px; }}
        .vulnerability {{ border: 1px solid #dee2e6; margin: 15px 0; padding: 15px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #0dcaf0; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Project:</strong> {summary['project_path']}</p>
        <p><strong>Files Scanned:</strong> {summary['files_scanned']}</p>
        <p><strong>Total Vulnerabilities:</strong> {summary['total_vulnerabilities']}</p>
        <p><strong>Critical:</strong> {summary['severity_breakdown']['critical']}</p>
        <p><strong>High:</strong> {summary['severity_breakdown']['high']}</p>
        <p><strong>Medium:</strong> {summary['severity_breakdown']['medium']}</p>
        <p><strong>Low:</strong> {summary['severity_breakdown']['low']}</p>
    </div>
    
    <h2>Vulnerabilities</h2>"""
        
        for vuln in scan_result.all_vulnerabilities:
            severity_class = vuln.severity.value.lower()
            html_template += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln.title}</h3>
        <p><strong>File:</strong> {vuln.location.file_path if vuln.location else 'Unknown'}</p>
        <p><strong>Line:</strong> {vuln.location.line_number if vuln.location else 'Unknown'}</p>
        <p><strong>Severity:</strong> {vuln.severity.value}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        {f'<p><strong>Remediation:</strong> {vuln.remediation}</p>' if vuln.remediation else ''}
    </div>"""
        
        html_template += """
</body>
</html>"""
        
        return html_template
    
    def _generate_markdown_report(self, scan_result: ScanResult) -> str:
        """Generate Markdown report"""
        
        summary = scan_result.get_summary()
        
        md_report = f"""# Security Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Project:** {summary['project_path']}
- **Files Scanned:** {summary['files_scanned']}
- **Total Vulnerabilities:** {summary['total_vulnerabilities']}

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | {summary['severity_breakdown']['critical']} |
| High | {summary['severity_breakdown']['high']} |
| Medium | {summary['severity_breakdown']['medium']} |
| Low | {summary['severity_breakdown']['low']} |

## Vulnerabilities

"""
        
        for i, vuln in enumerate(scan_result.all_vulnerabilities, 1):
            md_report += f"""### {i}. {vuln.title}

- **File:** {vuln.location.file_path if vuln.location else 'Unknown'}
- **Line:** {vuln.location.line_number if vuln.location else 'Unknown'}
- **Severity:** {vuln.severity.value}
- **OWASP:** {vuln.owasp_category}

{vuln.description}

{f'**Remediation:** {vuln.remediation}' if vuln.remediation else ''}

---

"""
        
        return md_report
'''
        
        # Write with UTF-8 encoding
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        print(f"Created {report_file}")

def create_config_files():
    """Create configuration files"""
    
    # Create config directory
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)
    
    # Create ai_config.yaml
    config_file = config_dir / "ai_config.yaml"
    if not config_file.exists():
        config_content = """ai_providers:
  huggingface:
    api_key: ${HUGGINGFACE_API_KEY}
    base_url: "https://api-inference.huggingface.co/models/"
    code_model: "microsoft/CodeBERT-base"
    text_model: "microsoft/DialoGPT-large"
    rate_limit: 30
    timeout: 30

analysis_settings:
  chunk_size: 500
  overlap: 25
  confidence_threshold: 0.6
  max_concurrent_requests: 2
  enable_caching: true
  cache_duration: 3600

supported_languages:
  - python
  - go
  - java
  - csharp

security_profiles:
  strict:
    min_severity: "Low"
    include_potential_issues: true
    
  standard:
    min_severity: "Medium"
    include_potential_issues: true
    
  production:
    min_severity: "High"
    include_potential_issues: false

owasp_categories:
  A01: "Broken Access Control"
  A02: "Cryptographic Failures"
  A03: "Injection"
  A04: "Insecure Design"
  A05: "Security Misconfiguration"
  A06: "Vulnerable and Outdated Components"
  A07: "Identification and Authentication Failures"
  A08: "Software and Data Integrity Failures"
  A09: "Security Logging and Monitoring Failures"
  A10: "Server-Side Request Forgery"
"""
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(config_content)
        print(f"Created {config_file}")
    
    # Create .env.example
    env_example = config_dir / ".env.example"
    if not env_example.exists():
        env_content = """# Hugging Face API Configuration
HUGGINGFACE_API_KEY=your_huggingface_api_key_here

# Optional: Redis for caching
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
"""
        
        with open(env_example, 'w', encoding='utf-8') as f:
            f.write(env_content)
        print(f"Created {env_example}")

def create_examples():
    """Create example vulnerable files"""
    
    examples_dir = Path("examples")
    examples_dir.mkdir(exist_ok=True)
    
    # Python example
    py_example = examples_dir / "vulnerable_python.py"
    if not py_example.exists():
        py_content = '''"""
Example vulnerable Python code for testing
"""
import sqlite3
import os
import pickle

def login(username, password):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(user_input):
    # Command Injection vulnerability
    os.system("ls " + user_input)

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)
'''
        
        with open(py_example, 'w', encoding='utf-8') as f:
            f.write(py_content)
        print(f"Created {py_example}")

def create_requirements():
    """Create requirements.txt"""
    
    req_file = Path("requirements.txt")
    if not req_file.exists():
        requirements = """# Hugging Face Integration
aiohttp>=3.8.0
requests>=2.28.0

# Code Parsing
tree-sitter>=0.20.0
tree-sitter-python>=0.20.0
tree-sitter-go>=0.20.0
tree-sitter-java>=0.20.0
tree-sitter-c-sharp>=0.20.0

# CLI & Interface
click>=8.0.0
rich>=13.0.0
pydantic>=2.0.0
pyyaml>=6.0.0

# Utilities
python-dotenv>=1.0.0
asyncio-throttle>=1.0.0

# Optional: for better caching
redis>=4.5.0
"""
        
        with open(req_file, 'w', encoding='utf-8') as f:
            f.write(requirements)
        print(f"Created {req_file}")

def fix_imports():
    """Check and fix common import issues"""
    
    print("\nChecking for common issues...")
    
    # Check if tree-sitter is installed
    try:
        import tree_sitter
        print("✓ tree-sitter is available")
    except ImportError:
        print("✗ tree-sitter not installed. Run: pip install tree-sitter")
    
    # Check for other required packages
    required_packages = ['aiohttp', 'click', 'rich', 'yaml', 'dotenv']
    for package in required_packages:
        try:
            if package == 'yaml':
                import yaml
            elif package == 'dotenv':
                import dotenv
            else:
                __import__(package)
            print(f"✓ {package} is available")
        except ImportError:
            print(f"✗ {package} not installed")

def main():
    """Main setup function"""
    
    print("Setting up AI Secure Code Review CLI Tool...")
    print("=" * 50)
    
    # Create necessary directories
    directories = ["core", "ai_models", "parsers", "utils", "reports", "config", "examples"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"Created directory: {directory}")
    
    # Create __init__.py files
    print("\nCreating __init__.py files...")
    create_init_files()
    
    # Create missing files
    print("\nCreating missing files...")
    create_missing_files()
    create_config_files()
    create_examples()
    create_requirements()
    
    # Check imports
    fix_imports()
    
    print("\nSetup complete!")
    print("\nNext steps:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Set up API key: python cli.py setup")
    print("3. Test: python cli.py test-ai")
    print("4. Scan: python cli.py scan --path examples")

if __name__ == "__main__":
    main()