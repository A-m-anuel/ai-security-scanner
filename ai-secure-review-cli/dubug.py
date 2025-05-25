#!/usr/bin/env python3
# debug_test.py - Test your specific Flask SSTI case

import asyncio
import logging
import sys
from pathlib import Path

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

async def test_flask_ssti():
    """Test your specific Flask SSTI example"""
    
    print("🧪 Testing Flask SSTI Detection")
    print("=" * 50)
    
    # Your exact vulnerable code
    test_code = '''from flask import request, render_template_string

@app.route('/hello')
def hello():
    username = request.args.get('username')
    template = f"<p>Hello {username}</p>"
    return render_template_string(template)
'''
    
    print("📝 Test Code:")
    print(test_code)
    print("=" * 50)
    
    try:
        # Import the necessary modules
        from core.models import CodeContext, Language
        from ai_models.huggingface_analyzer import HuggingFaceAnalyzer
        
        # Create context
        context = CodeContext(
            file_path="examples/vul.py",
            language=Language.PYTHON,
            imports=["flask"],
            functions=["hello"],
            classes=[],
            dependencies=[],
            framework="flask"
        )
        
        # Create analyzer in pattern-only mode (no API calls)
        config = {
            'api_key': None,  # Force pattern-only mode
            'base_url': 'https://api-inference.huggingface.co/models/',
            'code_model': 'microsoft/codebert-base',
            'rate_limit': 10
        }
        
        analyzer = HuggingFaceAnalyzer(config, pattern_only=True)
        
        print("🔍 Running analysis...")
        vulnerabilities = await analyzer.analyze_code(test_code, context)
        
        print(f"\n📊 RESULTS:")
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n🚨 Vulnerability {i}:")
                print(f"   Type: {vuln.type}")
                print(f"   Severity: {vuln.severity.value}")
                print(f"   Line: {vuln.location.line_number}")
                print(f"   Code: {vuln.vulnerable_code}")
                print(f"   Description: {vuln.description}")
                print(f"   OWASP: {vuln.owasp_category}")
                print(f"   Remediation: {vuln.remediation}")
        else:
            print("❌ No vulnerabilities found!")
            print("\n🔍 Debugging suggestions:")
            print("1. Check if patterns are matching correctly")
            print("2. Verify the code is being processed line by line")
            print("3. Check regex patterns for your specific case")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

async def test_simple_patterns():
    """Test individual lines to see what matches"""
    
    print("\n🔍 Testing Individual Patterns")
    print("=" * 50)
    
    test_lines = [
        'template = f"<p>Hello {username}</p>"',
        'return render_template_string(template)',
        'render_template_string(f"Hello {user}")',
        'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        'API_KEY = "sk-1234567890abcdef"',
        'os.system("ls " + user_input)'
    ]
    
    try:
        from ai_models.huggingface_analyzer import HuggingFaceAnalyzer
        from core.models import CodeContext, Language
        
        config = {'api_key': None}
        analyzer = HuggingFaceAnalyzer(config, pattern_only=True)
        
        patterns = analyzer._get_improved_vulnerability_patterns('python')
        
        for line in test_lines:
            print(f"\n📝 Testing line: {line}")
            
            matches = []
            for pattern_info in patterns:
                if analyzer._matches_pattern(line, pattern_info):
                    matches.append(pattern_info['name'])
            
            if matches:
                print(f"   ✅ Matches: {', '.join(matches)}")
            else:
                print(f"   ❌ No matches")
    
    except Exception as e:
        print(f"❌ Error during pattern testing: {e}")
        import traceback
        traceback.print_exc()

async def test_full_file_analysis():
    """Test analyzing your actual vul.py file"""
    
    print("\n📁 Testing Actual File Analysis")
    print("=" * 50)
    
    vul_file = Path("examples/vul.py")
    
    if not vul_file.exists():
        print(f"❌ File not found: {vul_file}")
        print("Creating the file for testing...")
        
        vul_file.parent.mkdir(exist_ok=True)
        
        content = '''from flask import request, render_template_string

@app.route('/hello')
def hello():
    username = request.args.get('username')
    template = f"<p>Hello {username}</p>"
    return render_template_string(template)
'''
        
        with open(vul_file, 'w') as f:
            f.write(content)
        
        print(f"✅ Created {vul_file}")
    
    try:
        # Test using the CLI approach
        print("🔧 Testing with CLI approach...")
        
        from core.language_detector import LanguageDetector
        from parsers.parser_factory import ParserFactory
        from ai_models.huggingface_analyzer import HuggingFaceAnalyzer
        
        # Detect language
        language = LanguageDetector.detect_from_file(str(vul_file))
        print(f"   Detected language: {language}")
        
        # Parse file
        parser = ParserFactory.get_parser(language)
        context = parser.parse_file(str(vul_file))
        print(f"   Parsed context: {context.functions}")
        
        # Read file
        with open(vul_file, 'r') as f:
            code = f.read()
        
        print(f"   File content ({len(code)} chars):")
        print(f"   {repr(code)}")
        
        # Analyze
        config = {'api_key': None}
        analyzer = HuggingFaceAnalyzer(config, pattern_only=True)
        
        vulnerabilities = await analyzer.analyze_code(code, context)
        
        print(f"\n📊 File Analysis Results:")
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        
        for vuln in vulnerabilities:
            print(f"   - {vuln.type} at line {vuln.location.line_number}")
    
    except Exception as e:
        print(f"❌ Error during file analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_flask_ssti())
    asyncio.run(test_simple_patterns())
    asyncio.run(test_full_file_analysis())