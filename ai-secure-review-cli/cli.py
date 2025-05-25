# cli.py - Fixed version with proper .env loading
import click
import asyncio
import yaml
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# Load environment variables FIRST - before anything else
from dotenv import load_dotenv

# Try to load .env from multiple locations
env_locations = [
    Path("config/.env"),
    Path(".env"),
    Path(__file__).parent / "config" / ".env",
    Path(__file__).parent / ".env"
]

for env_path in env_locations:
    if env_path.exists():
        load_dotenv(env_path)
        print(f"[DEBUG] Loaded environment from: {env_path}")
        break

# Now import rich and other modules
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

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
    """Load configuration from YAML files with proper .env handling"""
    config_dir = Path(__file__).parent / "config"
    
    try:
        # Load YAML config
        config_file = config_dir / "ai_config.yaml"
        if not config_file.exists():
            console.print(f"[red]Configuration file not found: {config_file}[/red]")
            return create_default_config()
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Replace environment variable placeholders
        for provider_name, settings in config.get('ai_providers', {}).items():
            if 'api_key' in settings and isinstance(settings['api_key'], str):
                if settings['api_key'].startswith('${') and settings['api_key'].endswith('}'):
                    env_var = settings['api_key'][2:-1]  # Remove ${ and }
                    api_key = os.getenv(env_var)
                    if api_key:
                        settings['api_key'] = api_key
                        console.print(f"[green]✓ API key loaded for {provider_name}[/green]")
                    else:
                        console.print(f"[yellow]⚠ Warning: {env_var} not found in environment[/yellow]")
                        settings['api_key'] = None
        
        return config
        
    except yaml.YAMLError as e:
        console.print(f"[red]Error parsing YAML configuration: {e}[/red]")
        return create_default_config()
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        return create_default_config()

def create_default_config():
    """Create default configuration when config file is missing"""
    return {
        'ai_providers': {
            'huggingface': {
                'api_key': os.getenv('HUGGINGFACE_API_KEY'),
                'base_url': 'https://api-inference.huggingface.co/models/',
                'code_model': 'microsoft/CodeBERT-base',
                'text_model': 'microsoft/DialoGPT-large',
                'rate_limit': 30,
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
        'security_profiles': {
            'strict': {'min_severity': 'Low', 'include_potential_issues': True},
            'standard': {'min_severity': 'Medium', 'include_potential_issues': True},
            'production': {'min_severity': 'High', 'include_potential_issues': False}
        },
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
    """AI-Powered Secure Code Review CLI Tool (Hugging Face Edition)
    
    Analyze your codebase for security vulnerabilities using Hugging Face models.
    Supports Python, Go, Java, and C# code analysis with free AI models.
    """
    pass

@cli.command()
@click.option('--path', '-p', required=True, help='Path to analyze (file or directory)')
@click.option('--ai-provider', default='huggingface', help='AI provider (only huggingface supported)')
@click.option('--model', help='Specific Hugging Face model to use')
@click.option('--languages', '-l', help='Comma-separated list of languages to analyze')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json', 'html', 'markdown']))
@click.option('--severity', default='medium', type=click.Choice(['low', 'medium', 'high', 'critical']))
@click.option('--exclude', help='Comma-separated patterns to exclude')
@click.option('--no-cache', is_flag=True, help='Disable result caching')
@click.option('--parallel', default=2, help='Number of parallel requests (keep low for free tier)')
@click.option('--profile', default='standard', help='Security analysis profile')
@click.option('--include-fixes', is_flag=True, help='Generate AI-powered fix suggestions')
@click.option('--pattern-only', is_flag=True, help='Use only pattern detection (faster, no API calls)')
def scan(path: str, ai_provider: str, model: Optional[str], languages: Optional[str], 
         output: Optional[str], output_format: str, severity: str, exclude: Optional[str],
         no_cache: bool, parallel: int, profile: str, include_fixes: bool, pattern_only: bool):
    """Scan code for security vulnerabilities using Hugging Face AI analysis"""
    
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
        console.print("Either set HUGGINGFACE_API_KEY environment variable or use --pattern-only flag")
        console.print("Get free API key at: https://huggingface.co/settings/tokens")
        
        if not click.confirm("Continue with pattern-only detection?"):
            sys.exit(1)
        pattern_only = True
    
    # Parse parameters
    target_languages = None
    if languages:
        target_languages = [lang.strip() for lang in languages.split(',')]
    
    exclude_patterns = []
    if exclude:
        exclude_patterns = [pattern.strip() for pattern in exclude.split(',')]
    
    # Initialize components
    cache_manager = CacheManager() if not no_cache else None
    token_counter = TokenCounter()
    
    # Adjust parallel requests for free tier
    if parallel > 3:
        console.print("[yellow]Warning: Reducing parallel requests to 3 for free tier limits[/yellow]")
        parallel = 3
    
    # Run analysis
    try:
        results = asyncio.run(
            run_analysis(
                path=path,
                config=config,
                ai_provider=ai_provider,
                model=model,
                target_languages=target_languages,
                exclude_patterns=exclude_patterns,
                cache_manager=cache_manager,
                token_counter=token_counter,
                parallel=parallel,
                profile=profile,
                include_fixes=include_fixes,
                min_severity=severity,
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
        
        # Print usage summary
        if not pattern_only:
            usage_summary = token_counter.get_usage_summary()
            console.print(f"\n[blue]API Requests: {usage_summary.get('total_requests', 0)}[/blue]")
        
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
        if "api" in str(e).lower():
            console.print("[blue]Tip: Try using --pattern-only flag for offline analysis[/blue]")
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
    
    # Create summary table
    table = Table(title="Project Statistics")
    table.add_column("Language", style="cyan")
    table.add_column("Files", justify="right", style="magenta")
    table.add_column("Lines", justify="right", style="green")
    
    for lang, stats in project_stats['by_language'].items():
        table.add_row(lang.title(), str(stats['files']), str(stats['lines']))
    
    table.add_row("TOTAL", str(project_stats['total_files']), str(project_stats['total_lines']), style="bold")
    
    console.print(table)
    
    # Show supported files
    supported_files = list(FileUtils.find_source_files(path))
    if supported_files:
        console.print(f"\n[green]Found {len(supported_files)} supported files for analysis[/green]")
    else:
        console.print(f"\n[yellow]No supported files found in {path}[/yellow]")

@cli.command()
@click.option('--provider', default='huggingface', help='AI provider to test')
def test_ai(provider: str):
    """Test Hugging Face API connection"""
    
    config = load_config()
    
    if provider not in config.get('ai_providers', {}):
        console.print(f"[red]Provider '{provider}' not configured[/red]")
        return
    
    api_key = config['ai_providers'][provider].get('api_key')
    if not api_key:
        console.print(f"[red]No API key found for {provider}[/red]")
        console.print("Set HUGGINGFACE_API_KEY environment variable")
        console.print("Get free API key at: https://huggingface.co/settings/tokens")
        return
    
    console.print(f"[blue]Testing {provider} connection...[/blue]")
    console.print(f"[dim]Using API key: {api_key[:8]}...[/dim]")
    
    try:
        # Simple test code
        test_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return execute_query(query)
"""
        
        from core.ai_analyzer import AIAnalyzer
        from core.models import CodeContext, Language
        
        analyzer = AIAnalyzer(config, provider)
        context = CodeContext(
            file_path="test.py",
            language=Language.PYTHON,
            imports=[],
            functions=["login"],
            classes=[],
            dependencies=[]
        )
        
        with console.status(f"[spinner]Testing {provider}..."):
            vulnerabilities = asyncio.run(analyzer.analyze_code(test_code, context))
        
        if vulnerabilities:
            console.print(f"[green]✓ {provider} is working! Found {len(vulnerabilities)} test vulnerabilities[/green]")
            
            # Show first vulnerability as example
            if vulnerabilities:
                vuln = vulnerabilities[0]
                console.print(f"[dim]Example: {vuln.type} - {vuln.severity.value}[/dim]")
        else:
            console.print(f"[yellow]⚠ {provider} connected but no vulnerabilities detected in test code[/yellow]")
            
    except Exception as e:
        console.print(f"[red]✗ Error testing {provider}: {e}[/red]")
        if "api" in str(e).lower():
            console.print("[blue]Check your API key and internet connection[/blue]")

@cli.command()
def setup():
    """Set up the tool with Hugging Face API key"""
    
    console.print("[blue]🚀 Setting up AI Secure Code Review CLI Tool[/blue]")
    console.print("\nThis tool uses Hugging Face's free API for AI-powered security analysis.")
    
    # Check if API key exists
    config_dir = Path(__file__).parent / "config"
    config_dir.mkdir(exist_ok=True)
    
    env_file = config_dir / ".env"
    
    current_key = None
    if env_file.exists():
        load_dotenv(env_file)
        current_key = os.getenv('HUGGINGFACE_API_KEY')
    
    if current_key:
        console.print(f"[green]✓ API key already configured: {current_key[:8]}...[/green]")
        if not click.confirm("Do you want to update it?"):
            return
    
    console.print("\n[yellow]Get your free API key from:[/yellow]")
    console.print("https://huggingface.co/settings/tokens")
    console.print("\n1. Go to the URL above")
    console.print("2. Click 'New token'")
    console.print("3. Give it a name (e.g., 'code-review-tool')")
    console.print("4. Select 'Read' role")
    console.print("5. Copy the generated token\n")
    
    api_key = click.prompt("Enter your Hugging Face API key", hide_input=True)
    
    if not api_key.startswith('hf_'):
        console.print("[yellow]Warning: Hugging Face tokens usually start with 'hf_'[/yellow]")
    
    # Write to .env file
    env_content = f"HUGGINGFACE_API_KEY={api_key}\n"
    
    with open(env_file, 'w', encoding='utf-8') as f:
        f.write(env_content)
    
    # Also set for current session
    os.environ['HUGGINGFACE_API_KEY'] = api_key
    
    console.print("[green]✓ API key saved successfully![/green]")
    console.print("\nTesting connection...")
    
    # Test the connection
    try:
        # Import test command and run it
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(test_ai, ['--provider', 'huggingface'])
        
        if result.exit_code == 0:
            console.print("[green]✅ Setup complete! You're ready to scan code.[/green]")
        else:
            console.print("[yellow]⚠ Setup complete but connection test failed.[/yellow]")
            console.print("Try running: ai-secure-review test-ai")
    except Exception:
        console.print("[blue]Setup complete! Test with: ai-secure-review test-ai[/blue]")

@cli.command()
def clear_cache():
    """Clear analysis cache"""
    
    cache_manager = CacheManager()
    cache_manager.clear()
    console.print("[green]Cache cleared successfully[/green]")

async def run_analysis(path: str, config: dict, ai_provider: str, model: Optional[str],
                      target_languages: Optional[List[str]], exclude_patterns: List[str],
                      cache_manager: Optional[CacheManager], token_counter: TokenCounter,
                      parallel: int, profile: str, include_fixes: bool, min_severity: str,
                      pattern_only: bool = False):
    """Run the main analysis process"""
    
    from core.ai_analyzer import AIAnalyzer
    from core.models import ScanResult
    from parsers.parser_factory import ParserFactory
    import uuid
    
    # Initialize analyzer with pattern_only flag
    analyzer = AIAnalyzer(config, ai_provider, model, pattern_only=pattern_only)
    
    # Create scan result
    scan_result = ScanResult(
        project_path=path,
        scan_id=str(uuid.uuid4()),
        start_time=datetime.now(),
        ai_provider=ai_provider if not pattern_only else 'pattern-only'
    )
    
    # Find files to analyze
    if os.path.isfile(path):
        files_to_analyze = [path]
    else:
        files_to_analyze = []
        for file_path in FileUtils.find_source_files(path):
            if FileUtils.should_exclude_file(file_path, exclude_patterns):
                continue
            
            if target_languages:
                detected_lang = LanguageDetector.detect_from_file(file_path)
                if not detected_lang or detected_lang.value not in target_languages:
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
        
        task = progress.add_task(f"Analyzing files...", total=len(files_to_analyze))
        
        # Process files in batches for parallel processing
        semaphore = asyncio.Semaphore(parallel)
        tasks = []
        
        for file_path in files_to_analyze:
            task_coro = analyze_single_file(
                file_path, analyzer, cache_manager, token_counter, 
                include_fixes, semaphore, progress, task, pattern_only
            )
            tasks.append(task_coro)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                console.print(f"[red]Error analyzing {files_to_analyze[i]}: {result}[/red]")
            elif result:
                scan_result.file_results.append(result)
    
    # Update scan statistics
    scan_result.end_time = datetime.now()
    scan_result.total_files_scanned = len(scan_result.file_results)
    scan_result.total_vulnerabilities = len(scan_result.all_vulnerabilities)
    
    return scan_result

async def analyze_single_file(file_path: str, analyzer, cache_manager: Optional[CacheManager],
                             token_counter: TokenCounter, include_fixes: bool,
                             semaphore: asyncio.Semaphore, progress, task_id, pattern_only: bool = False):
    """Analyze a single file"""
    
    from core.models import AnalysisResult
    from parsers.parser_factory import ParserFactory
    from ai_models.huggingface_analyzer import HuggingFaceAnalyzer
    import time
    
    async with semaphore:
        try:
            # Detect language
            language = LanguageDetector.detect_from_file(file_path)
            if not language:
                return None
            
            # Get parser
            parser = ParserFactory.get_parser(language)
            if not parser:
                console.print(f"[yellow]No parser available for {language.value}[/yellow]")
                return None
            
            # Parse file context
            context = parser.parse_file(file_path)
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Check cache
            cache_key = {'file_path': file_path, 'code_hash': hash(code), 'pattern_only': pattern_only}
            cached_result = None
            if cache_manager:
                cached_result = cache_manager.get(cache_key)
            
            if cached_result:
                # Use cached result
                result = AnalysisResult(
                    file_path=file_path,
                    language=language,
                    vulnerabilities=cached_result['vulnerabilities'],
                    analysis_time=0,
                    token_usage=0,
                    ai_model_used=cached_result.get('model', 'cached')
                )
            else:
                # Perform analysis
                start_time = time.time()
                
                if pattern_only or not analyzer:
                    # Pattern-only analysis
                    from ai_models.huggingface_analyzer import HuggingFaceAnalyzer
                    pattern_analyzer = HuggingFaceAnalyzer({'api_key': 'dummy'})
                    vulnerabilities = pattern_analyzer._detect_pattern_vulnerabilities(code, context)
                    model_used = 'pattern-detection'
                    token_usage = 0
                else:
                    # Full AI analysis
                    vulnerabilities = await analyzer.analyze_code(code, context)
                    model_used = analyzer.model_name
                    token_usage = analyzer.get_token_count(code)
                    token_counter.add_usage(model_used, token_usage, 0)
                
                analysis_time = time.time() - start_time
                
                # Generate fixes if requested and not pattern-only
                if include_fixes and vulnerabilities and not pattern_only and analyzer:
                    for vuln in vulnerabilities:
                        if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                            vuln.fix_suggestion = await analyzer.generate_fix(vuln, code)
                
                result = AnalysisResult(
                    file_path=file_path,
                    language=language,
                    vulnerabilities=vulnerabilities,
                    analysis_time=analysis_time,
                    token_usage=token_usage,
                    ai_model_used=model_used
                )
                
                # Cache result
                if cache_manager:
                    cache_data = {
                        'vulnerabilities': [v.to_dict() for v in vulnerabilities],
                        'model': model_used
                    }
                    cache_manager.set(cache_key, cache_data)
            
            progress.advance(task_id)
            return result
            
        except Exception as e:
            console.print(f"[red]Error analyzing {file_path}: {e}[/red]")
            progress.advance(task_id)
            return None

if __name__ == '__main__':
    cli()