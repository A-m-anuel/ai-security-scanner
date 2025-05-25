# cli.py - CLEANED VERSION
import click
import asyncio
import yaml
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# Load environment variables FIRST
from dotenv import load_dotenv

# Load .env file
env_file = Path("config/.env")
if env_file.exists():
    load_dotenv(env_file)

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import our modules
from core.models import Language, Severity
from core.language_detector import LanguageDetector
from core.ai_analyzer import AIAnalyzer
from utils.file_utils import FileUtils
from utils.cache_manager import CacheManager
from utils.token_counter import TokenCounter
from reports.ai_report_generator import AIReportGenerator

console = Console()

def load_config():
    """Load configuration - SIMPLIFIED"""
    config_dir = Path(__file__).parent / "config"
    
    try:
        config_file = config_dir / "ai_config.yaml"
        if not config_file.exists():
            console.print(f"[red]Configuration file not found: {config_file}[/red]")
            return create_default_config()
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Replace environment variable placeholders
        hf_config = config.get('ai_providers', {}).get('huggingface', {})
        if 'api_key' in hf_config:
            if isinstance(hf_config['api_key'], str) and hf_config['api_key'].startswith('${'):
                env_var = hf_config['api_key'][2:-1]  # Remove ${ and }
                api_key = os.getenv(env_var)
                if api_key:
                    hf_config['api_key'] = api_key
                    console.print(f"[green]✓ API key loaded for huggingface[/green]")
                else:
                    console.print(f"[yellow]⚠ Warning: {env_var} not found in environment[/yellow]")
                    hf_config['api_key'] = None
        
        return config
        
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        return create_default_config()

def create_default_config():
    """Create default configuration"""
    return {
        'ai_providers': {
            'huggingface': {
                'api_key': os.getenv('HUGGINGFACE_API_KEY'),
                'base_url': 'https://api-inference.huggingface.co/models/',
                'code_model': 'microsoft/codebert-base',
                'text_model': 'microsoft/DialoGPT-medium',
                'rate_limit': 10,
                'timeout': 30
            }
        },
        'analysis_settings': {
            'chunk_size': 500,
            'overlap': 25,
            'confidence_threshold': 0.6,
            'max_concurrent_requests': 2,
            'enable_caching': True,
            'cache_duration': 3600
        },
        'supported_languages': ['python', 'go', 'java', 'csharp'],
        'owasp_categories': {
            'A01': 'Broken Access Control',
            'A02': 'Cryptographic Failures',
            'A03': 'Injection',
            'A04': 'Insecure Design',
            'A05': 'Security Misconfiguration',
            'A06': 'Vulnerable and Outdated Components',
            'A07': 'Identification and Authentication Failures',
            'A08': 'Software and Data Integrity Failures',
            'A09': 'Security Logging and Monitoring Failures',
            'A10': 'Server-Side Request Forgery'
        }
    }

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """AI-Powered Secure Code Review CLI Tool"""
    pass

@cli.command()
@click.option('--path', '-p', required=True, help='Path to analyze (file or directory)')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json', 'html', 'markdown']))
@click.option('--pattern-only', is_flag=True, help='Use only pattern detection (no API calls)')
@click.option('--exclude', help='Comma-separated patterns to exclude')
def scan(path: str, output: Optional[str], output_format: str, pattern_only: bool, exclude: Optional[str]):
    """Scan code for security vulnerabilities"""
    
    # Load configuration
    config = load_config()
    
    # Validate path
    if not os.path.exists(path):
        console.print(f"[red]Error: Path '{path}' does not exist[/red]")
        sys.exit(1)
    
    # Check API key if not using pattern-only mode
    hf_key = config['ai_providers']['huggingface'].get('api_key')
    if not hf_key and not pattern_only:
        console.print("[yellow]Warning: No Hugging Face API key found.[/yellow]")
        console.print("Get free API key at: https://huggingface.co/settings/tokens")
        console.print("Using pattern-only detection.")
        pattern_only = True
    
    # Parse exclude patterns
    exclude_patterns = []
    if exclude:
        exclude_patterns = [pattern.strip() for pattern in exclude.split(',')]
    
    # Run analysis
    try:
        results = asyncio.run(
            run_analysis(
                path=path,
                config=config,
                exclude_patterns=exclude_patterns,
                pattern_only=pattern_only
            )
        )
        
        # Generate report
        report_generator = AIReportGenerator(config)
        
        if output_format == 'table':
            report_generator.print_console_report(results, console)
        else:
            report_content = report_generator.generate_report(results, output_format)
            
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                console.print(f"[green]Report saved to: {output}[/green]")
            else:
                console.print(report_content)
        
        # Exit with appropriate code
        critical_count = len([v for v in results.all_vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in results.all_vulnerabilities if v.severity == Severity.HIGH])
        
        if critical_count > 0:
            sys.exit(2)  # Critical vulnerabilities found
        elif high_count > 0:
            sys.exit(1)  # High severity vulnerabilities found
        else:
            sys.exit(0)  # No critical/high vulnerabilities
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--path', '-p', required=True, help='Path to analyze')
def stats(path: str):
    """Show project statistics"""
    
    if not os.path.exists(path):
        console.print(f"[red]Error: Path '{path}' does not exist[/red]")
        return
    
    console.print(f"[blue]Analyzing project structure: {path}[/blue]")
    
    with console.status("[spinner]Scanning files..."):
        project_stats = FileUtils.get_project_stats(path)
    
    from rich.table import Table
    table = Table(title="Project Statistics")
    table.add_column("Language", style="cyan")
    table.add_column("Files", justify="right", style="magenta")
    table.add_column("Lines", justify="right", style="green")
    
    for lang, stats in project_stats['by_language'].items():
        table.add_row(lang.title(), str(stats['files']), str(stats['lines']))
    
    table.add_row("TOTAL", str(project_stats['total_files']), str(project_stats['total_lines']), style="bold")
    
    console.print(table)

@cli.command()
def test_ai():
    """Test Hugging Face API connection"""
    
    config = load_config()
    
    api_key = config['ai_providers']['huggingface'].get('api_key')
    if not api_key:
        console.print("[red]No API key found for HuggingFace[/red]")
        console.print("Set HUGGINGFACE_API_KEY environment variable")
        return
    
    console.print("[blue]Testing HuggingFace connection...[/blue]")
    
    try:
        test_code = '''
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return execute_query(query)
'''
        
        from core.ai_analyzer import AIAnalyzer
        from core.models import CodeContext, Language
        
        analyzer = AIAnalyzer(config, 'huggingface')
        context = CodeContext(
            file_path="test.py",
            language=Language.PYTHON,
            imports=[],
            functions=["login"],
            classes=[],
            dependencies=[]
        )
        
        with console.status("[spinner]Testing HuggingFace..."):
            vulnerabilities = asyncio.run(analyzer.analyze_code(test_code, context))
        
        if vulnerabilities:
            console.print(f"[green]✓ HuggingFace is working! Found {len(vulnerabilities)} test vulnerabilities[/green]")
            for vuln in vulnerabilities:
                console.print(f"[dim]  - {vuln.type}: {vuln.severity.value}[/dim]")
        else:
            console.print("[yellow]⚠ HuggingFace connected but no vulnerabilities detected[/yellow]")
            
    except Exception as e:
        console.print(f"[red]✗ Error testing HuggingFace: {e}[/red]")

@cli.command()
def setup():
    """Set up the tool with Hugging Face API key"""
    
    console.print("[blue]🚀 Setting up AI Secure Code Review CLI Tool[/blue]")
    
    # Check if API key exists
    config_dir = Path(__file__).parent / "config"
    config_dir.mkdir(exist_ok=True)
    
    env_file = config_dir / ".env"
    
    current_key = None
    if env_file.exists():
        load_dotenv(env_file)
        current_key = os.getenv('HUGGINGFACE_API_KEY')
    
    if current_key:
        console.print(f"[green]✓ API key already configured[/green]")
        if not click.confirm("Do you want to update it?"):
            return
    
    console.print("\n[yellow]Get your free API key from:[/yellow]")
    console.print("https://huggingface.co/settings/tokens")
    
    api_key = click.prompt("Enter your Hugging Face API key", hide_input=True)
    
    # Write to .env file
    env_content = f"HUGGINGFACE_API_KEY={api_key}\n"
    
    with open(env_file, 'w', encoding='utf-8') as f:
        f.write(env_content)
    
    os.environ['HUGGINGFACE_API_KEY'] = api_key
    
    console.print("[green]✓ API key saved successfully![/green]")
    console.print("Test with: python cli.py test-ai")

async def run_analysis(path: str, config: dict, exclude_patterns: List[str], pattern_only: bool = False):
    """Run the main analysis process - SIMPLIFIED"""
    
    from core.ai_analyzer import AIAnalyzer
    from core.models import ScanResult
    from parsers.parser_factory import ParserFactory
    import uuid
    
    # Initialize analyzer
    analyzer = AIAnalyzer(config, 'huggingface', pattern_only=pattern_only)
    
    # Create scan result
    scan_result = ScanResult(
        project_path=path,
        scan_id=str(uuid.uuid4()),
        start_time=datetime.now(),
        ai_provider='huggingface' if not pattern_only else 'pattern-only'
    )
    
    # Find files to analyze
    if os.path.isfile(path):
        files_to_analyze = [path]
    else:
        files_to_analyze = []
        for file_path in FileUtils.find_source_files(path):
            if FileUtils.should_exclude_file(file_path, exclude_patterns):
                continue
            files_to_analyze.append(file_path)
    
    if not files_to_analyze:
        console.print("[yellow]No files found to analyze[/yellow]")
        return scan_result
    
    console.print(f"[blue]Found {len(files_to_analyze)} files to analyze[/blue]")
    
    # Analyze files with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Analyzing files...", total=len(files_to_analyze))
        
        for file_path in files_to_analyze:
            try:
                result = await analyze_single_file(file_path, analyzer, progress, task)
                if result:
                    scan_result.file_results.append(result)
            except Exception as e:
                console.print(f"[red]Error analyzing {file_path}: {e}[/red]")
                progress.advance(task)
    
    # Update scan statistics
    scan_result.end_time = datetime.now()
    scan_result.total_files_scanned = len(scan_result.file_results)
    scan_result.total_vulnerabilities = len(scan_result.all_vulnerabilities)
    
    return scan_result

async def analyze_single_file(file_path: str, analyzer, progress, task_id):
    """Analyze a single file - SIMPLIFIED"""
    
    from core.models import AnalysisResult
    from parsers.parser_factory import ParserFactory
    import time
    
    try:
        # Detect language
        language = LanguageDetector.detect_from_file(file_path)
        if not language:
            progress.advance(task_id)
            return None
        
        # Get parser
        parser = ParserFactory.get_parser(language)
        if not parser:
            progress.advance(task_id)
            return None
        
        # Parse file context
        context = parser.parse_file(file_path)
        
        # Read file content
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        # Perform analysis
        start_time = time.time()
        vulnerabilities = await analyzer.analyze_code(code, context)
        analysis_time = time.time() - start_time
        
        result = AnalysisResult(
            file_path=file_path,
            language=language,
            vulnerabilities=vulnerabilities,
            analysis_time=analysis_time,
            token_usage=analyzer.get_token_count(code),
            ai_model_used=analyzer.model_name
        )
        
        progress.advance(task_id)
        return result
        
    except Exception as e:
        console.print(f"[red]Error analyzing {file_path}: {e}[/red]")
        progress.advance(task_id)
        return None

if __name__ == '__main__':
    cli()