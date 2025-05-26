
import json
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

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
        
        # Summary panel
        summary = scan_result.get_summary()
        
        summary_text = f"""
[bold blue]Scan Summary[/bold blue]
Project: {summary['project_path']}
Duration: {summary['duration']:.2f} seconds
Files Scanned: {summary['files_scanned']}
AI Provider: {summary['ai_provider']}

[bold red]Critical: {summary['severity_breakdown']['critical']}[/bold red]
[bold yellow]High: {summary['severity_breakdown']['high']}[/bold yellow]
[bold blue]Medium: {summary['severity_breakdown']['medium']}[/bold blue]
[bold green]Low: {summary['severity_breakdown']['low']}[/bold green]
Info: {summary['severity_breakdown']['info']}

Total Vulnerabilities: {summary['total_vulnerabilities']}
"""
        
        console.print(Panel(summary_text, title="Security Scan Results"))
        
        # Show vulnerabilities by severity
        vulnerabilities = scan_result.all_vulnerabilities
        if not vulnerabilities:
            console.print("[green]🎉 No vulnerabilities found![/green]")
            return
        
        # Group by severity
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: []
        }
        
        for vuln in vulnerabilities:
            by_severity[vuln.severity].append(vuln)
        
        # Display each severity group
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            vulns = by_severity[severity]
            if not vulns:
                continue
            
            # Color mapping
            colors = {
                Severity.CRITICAL: "bright_red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "cyan"
            }
            
            color = colors[severity]
            console.print(f"\n[{color}]■ {severity.value} Severity ({len(vulns)} issues)[/{color}]")
            
            # Create table for this severity
            table = Table(show_header=True, header_style=f"bold {color}")
            table.add_column("File", style="cyan", no_wrap=True)
            table.add_column("Line", justify="right", style="magenta")
            table.add_column("Issue", style="white")
            table.add_column("OWASP", style="green")
            table.add_column("Confidence", justify="right")
            
            for vuln in vulns:
                location = vuln.location
                file_path = Path(location.file_path).name if location else "Unknown"
                line_num = str(location.line_number) if location else "?"
                confidence = f"{vuln.confidence:.0%}" if vuln.confidence else "N/A"
                
                table.add_row(
                    file_path,
                    line_num,
                    vuln.title,
                    vuln.owasp_category.split(' - ')[0] if ' - ' in vuln.owasp_category else vuln.owasp_category,
                    confidence
                )
            
            console.print(table)
        
        # Show detailed view for critical/high issues
        critical_high = by_severity[Severity.CRITICAL] + by_severity[Severity.HIGH]
        if critical_high:
            console.print("\n[bold red]🚨 Critical & High Severity Details[/bold red]")
            
            for i, vuln in enumerate(critical_high[:5], 1):  # Show top 5
                self._print_vulnerability_detail(vuln, console, i)
        
        # OWASP Top 10 breakdown
        owasp_breakdown = summary['owasp_breakdown']
        if owasp_breakdown:
            console.print("\n[bold blue]OWASP Top 10 2021 Breakdown[/bold blue]")
            
            owasp_table = Table()
            owasp_table.add_column("Category", style="cyan")
            owasp_table.add_column("Count", justify="right", style="magenta")
            owasp_table.add_column("Description", style="white")
            
            for category, count in sorted(owasp_breakdown.items(), key=lambda x: x[1], reverse=True):
                description = self.owasp_categories.get(category.split(':')[0], "Unknown")
                owasp_table.add_row(category, str(count), description)
            
            console.print(owasp_table)
    
    def _print_vulnerability_detail(self, vuln: Vulnerability, console: Console, index: int):
        """Print detailed vulnerability information"""
        
        severity_colors = {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan"
        }
        
        color = severity_colors.get(vuln.severity, "white")
        
        detail_text = f"""
[bold {color}]{index}. {vuln.title}[/bold {color}]
[dim]File:[/dim] {vuln.location.file_path if vuln.location else 'Unknown'}
[dim]Line:[/dim] {vuln.location.line_number if vuln.location else 'Unknown'}
[dim]Severity:[/dim] [{color}]{vuln.severity.value}[/{color}]
[dim]OWASP:[/dim] {vuln.owasp_category}
[dim]Confidence:[/dim] {vuln.confidence:.0%}

[dim]Description:[/dim]
{vuln.description}

[dim]Attack Vector:[/dim]
{vuln.attack_vector or 'Not specified'}

[dim]Remediation:[/dim]
{vuln.remediation or 'No specific guidance provided'}
"""
        
        if vuln.vulnerable_code:
            detail_text += f"\n[dim]Vulnerable Code:[/dim]\n[red]{vuln.vulnerable_code}[/red]"
        
        if vuln.fix_suggestion:
            detail_text += f"\n[dim]AI Fix Suggestion:[/dim]\n[green]{vuln.fix_suggestion}[/green]"
        
        console.print(Panel(detail_text, border_style=color))
    
    def _generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate JSON report"""
        return json.dumps(scan_result.to_dict(), indent=2, default=str)
    
    def _generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate HTML report"""
        
        summary = scan_result.get_summary()
        vulnerabilities = scan_result.all_vulnerabilities
        
        # Group vulnerabilities by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 6px; margin-bottom: 30px; }}
        .metric {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #0dcaf0; }}
        .info {{ color: #6c757d; }}
        .vulnerability {{ border: 1px solid #dee2e6; margin: 15px 0; border-radius: 6px; }}
        .vuln-header {{ padding: 15px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; }}
        .vuln-body {{ padding: 15px; }}
        .code-block {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }}
        .severity-badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }}
        .owasp-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .owasp-table th, .owasp-table td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
        .owasp-table th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Scan Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Project:</strong> {summary['project_path']}</p>
            <p><strong>Duration:</strong> {summary['duration']:.2f} seconds</p>
            <p><strong>Files Scanned:</strong> {summary['files_scanned']}</p>
            <p><strong>AI Provider:</strong> {summary['ai_provider']}</p>
            
            <div style="text-align: center; margin-top: 20px;">
                <div class="metric">
                    <div class="metric-value critical">{summary['severity_breakdown']['critical']}</div>
                    <div>Critical</div>
                </div>
                <div class="metric">
                    <div class="metric-value high">{summary['severity_breakdown']['high']}</div>
                    <div>High</div>
                </div>
                <div class="metric">
                    <div class="metric-value medium">{summary['severity_breakdown']['medium']}</div>
                    <div>Medium</div>
                </div>
                <div class="metric">
                    <div class="metric-value low">{summary['severity_breakdown']['low']}</div>
                    <div>Low</div>
                </div>
                <div class="metric">
                    <div class="metric-value info">{summary['severity_breakdown']['info']}</div>
                    <div>Info</div>
                </div>
            </div>
        </div>
        
        <h2>Vulnerabilities</h2>
"""
        
        # Add vulnerabilities
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity in by_severity:
                html_template += f'<h3 class="{severity.lower()}">{severity} Severity ({len(by_severity[severity])} issues)</h3>'
                
                for vuln in by_severity[severity]:
                    html_template += self._vulnerability_to_html(vuln, severity.lower())
        
        # Add OWASP breakdown
        if summary['owasp_breakdown']:
            html_template += """
        <h2>OWASP Top 10 2021 Breakdown</h2>
        <table class="owasp-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Count</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"""
            for category, count in sorted(summary['owasp_breakdown'].items(), key=lambda x: x[1], reverse=True):
                description = self.owasp_categories.get(category.split(':')[0], "Unknown")
                html_template += f"""
                <tr>
                    <td>{category}</td>
                    <td>{count}</td>
                    <td>{description}</td>
                </tr>
"""
            
            html_template += """
            </tbody>
        </table>
"""
        
        html_template += """
    </div>
</body>
</html>
"""
        
        return html_template
    
    def _vulnerability_to_html(self, vuln: Vulnerability, severity_class: str) -> str:
        """Convert vulnerability to HTML"""
        
        location = vuln.location
        file_path = location.file_path if location else "Unknown"
        line_num = location.line_number if location else "Unknown"
        
        html = f"""
        <div class="vulnerability">
            <div class="vuln-header">
                <h4>{vuln.title} <span class="severity-badge {severity_class}">{vuln.severity.value}</span></h4>
                <p><strong>File:</strong> {file_path} <strong>Line:</strong> {line_num}</p>
                <p><strong>OWASP:</strong> {vuln.owasp_category} <strong>Confidence:</strong> {vuln.confidence:.0%}</p>
            </div>
            <div class="vuln-body">
                <p><strong>Description:</strong></p>
                <p>{vuln.description}</p>
                
                {f'<p><strong>Attack Vector:</strong></p><p>{vuln.attack_vector}</p>' if vuln.attack_vector else ''}
                {f'<p><strong>Business Impact:</strong></p><p>{vuln.business_impact}</p>' if vuln.business_impact else ''}
                
                {f'<p><strong>Vulnerable Code:</strong></p><div class="code-block">{vuln.vulnerable_code}</div>' if vuln.vulnerable_code else ''}
                {f'<p><strong>Fix Suggestion:</strong></p><div class="code-block">{vuln.fix_suggestion}</div>' if vuln.fix_suggestion else ''}
                
                <p><strong>Remediation:</strong></p>
                <p>{vuln.remediation or 'No specific guidance provided'}</p>
            </div>
        </div>
"""
        return html
    
    def _generate_markdown_report(self, scan_result: ScanResult) -> str:
        """Generate Markdown report"""
        
        summary = scan_result.get_summary()
        vulnerabilities = scan_result.all_vulnerabilities
        
        md_report = f"""# 🔒 Security Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Scan Summary

- **Project:** {summary['project_path']}
- **Duration:** {summary['duration']:.2f} seconds
- **Files Scanned:** {summary['files_scanned']}
- **AI Provider:** {summary['ai_provider']}

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['severity_breakdown']['critical']} |
| 🟠 High | {summary['severity_breakdown']['high']} |
| 🟡 Medium | {summary['severity_breakdown']['medium']} |
| 🔵 Low | {summary['severity_breakdown']['low']} |
| ⚪ Info | {summary['severity_breakdown']['info']} |

**Total Vulnerabilities:** {summary['total_vulnerabilities']}

## Vulnerabilities

"""
        
        # Group vulnerabilities by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Add vulnerabilities by severity
        severity_icons = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🔵',
            'Info': '⚪'
        }
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity in by_severity:
                icon = severity_icons.get(severity, '●')
                md_report += f"\n### {icon} {severity} Severity ({len(by_severity[severity])} issues)\n\n"
                
                for i, vuln in enumerate(by_severity[severity], 1):
                    md_report += self._vulnerability_to_markdown(vuln, i)
        
        # Add OWASP breakdown
        if summary['owasp_breakdown']:
            md_report += "\n## OWASP Top 10 2021 Breakdown\n\n"
            md_report += "| Category | Count | Description |\n"
            md_report += "|----------|-------|-------------|\n"
            
            for category, count in sorted(summary['owasp_breakdown'].items(), key=lambda x: x[1], reverse=True):
                description = self.owasp_categories.get(category.split(':')[0], "Unknown")
                md_report += f"| {category} | {count} | {description} |\n"
        
        return md_report
    
    def _vulnerability_to_markdown(self, vuln: Vulnerability, index: int) -> str:
        """Convert vulnerability to Markdown"""
        
        location = vuln.location
        file_path = location.file_path if location else "Unknown"
        line_num = location.line_number if location else "Unknown"
        
        md = f"""
#### {index}. {vuln.title}

- **File:** `{file_path}`
- **Line:** {line_num}
- **OWASP:** {vuln.owasp_category}
- **Confidence:** {vuln.confidence:.0%}

**Description:**
{vuln.description}

"""
        
        if vuln.attack_vector:
            md += f"**Attack Vector:**\n{vuln.attack_vector}\n\n"
        
        if vuln.business_impact:
            md += f"**Business Impact:**\n{vuln.business_impact}\n\n"
        
        if vuln.vulnerable_code:
            md += f"**Vulnerable Code:**\n```\n{vuln.vulnerable_code}\n```\n\n"
        
        if vuln.fix_suggestion:
            md += f"**Fix Suggestion:**\n```\n{vuln.fix_suggestion}\n```\n\n"
        
        md += f"**Remediation:**\n{vuln.remediation or 'No specific guidance provided'}\n\n"
        md += "---\n\n"
        
        return md