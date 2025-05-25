# test_integration.py
"""
Integration test script for AI Secure Code Review CLI Tool
Run this to verify your setup is working correctly
"""

import asyncio
import tempfile
import os
from pathlib import Path

# Test vulnerable code samples
VULNERABLE_PYTHON_CODE = '''
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

VULNERABLE_GO_CODE = '''
package main

import (
    "database/sql"
    "os/exec"
    _ "github.com/go-sql-driver/mysql"
)

func getUser(db *sql.DB, username string) error {
    // SQL Injection vulnerability
    query := "SELECT * FROM users WHERE username = '" + username + "'"
    rows, err := db.Query(query)
    if err != nil {
        return err
    }
    defer rows.Close()
    return nil
}

func executeCommand(userInput string) error {
    // Command Injection vulnerability  
    cmd := exec.Command("sh", "-c", "ls "+userInput)
    return cmd.Run()
}

const APIKey = "sk-1234567890abcdef"
'''

async def test_basic_functionality():
    """Test basic functionality without AI providers"""
    print("🧪 Testing basic functionality...")
    
    try:
        # Test language detection
        from core.language_detector import LanguageDetector
        from core.models import Language
        
        # Test Python detection
        assert LanguageDetector.detect_from_file("test.py") == Language.PYTHON
        assert LanguageDetector.detect_from_file("test.go") == Language.GO
        print("✅ Language detection working")
        
        # Test parsers
        from parsers.python_parser import PythonParser
        from parsers.go_parser import GoParser
        
        # Create temporary files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test Python parser
            py_file = Path(temp_dir) / "test.py"
            py_file.write_text(VULNERABLE_PYTHON_CODE)
            
            python_parser = PythonParser()
            py_context = python_parser.parse_file(str(py_file))
            
            assert py_context.language == Language.PYTHON
            assert len(py_context.functions) > 0
            assert len(py_context.imports) > 0
            print("✅ Python parser working")
            
            # Test Go parser
            go_file = Path(temp_dir) / "test.go"
            go_file.write_text(VULNERABLE_GO_CODE)
            
            go_parser = GoParser()
            go_context = go_parser.parse_file(str(go_file))
            
            assert go_context.language == Language.GO
            assert len(go_context.functions) > 0
            print("✅ Go parser working")
        
        # Test file utilities
        from utils.file_utils import FileUtils
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            (Path(temp_dir) / "test.py").write_text("print('hello')")
            (Path(temp_dir) / "test.go").write_text("package main")
            (Path(temp_dir) / "README.md").write_text("# Test")
            
            source_files = list(FileUtils.find_source_files(temp_dir))
            assert len(source_files) == 2  # Only .py and .go files
            print("✅ File utilities working")
        
        print("🎉 Basic functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

async def test_ai_integration():
    """Test AI integration (requires API keys)"""
    print("\n🤖 Testing AI integration...")
    
    try:
        # Load configuration
        import yaml
        from pathlib import Path
        
        config_path = Path("config/ai_config.yaml")
        if not config_path.exists():
            print("⚠️ No AI configuration found, skipping AI tests")
            return True
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Load environment variables for API keys
        from dotenv import load_dotenv
        load_dotenv(Path("config/.env"))
        
        # Check if OpenAI is available
        openai_config = config.get('ai_providers', {}).get('openai', {})
        api_key = os.getenv('OPENAI_API_KEY')
        
        if not api_key:
            print("⚠️ No OpenAI API key found, skipping AI tests")
            return True
        
        # Test OpenAI analyzer
        from ai_models.openai_analyzer import OpenAIAnalyzer
        from core.models import CodeContext, Language
        
        openai_config['api_key'] = api_key
        analyzer = OpenAIAnalyzer(openai_config)
        
        # Simple test
        test_context = CodeContext(
            file_path="test.py",
            language=Language.PYTHON,
            imports=["sqlite3", "os"],
            functions=["login"],
            classes=[],
            dependencies=[]
        )
        
        vulnerabilities = await analyzer.analyze_code(VULNERABLE_PYTHON_CODE, test_context)
        
        if vulnerabilities:
            print(f"✅ AI analysis working - found {len(vulnerabilities)} vulnerabilities")
            for vuln in vulnerabilities[:2]:  # Show first 2
                print(f"   - {vuln.type}: {vuln.severity.value}")
        else:
            print("⚠️ AI analysis returned no vulnerabilities (might be a prompt issue)")
        
        return True
        
    except Exception as e:
        print(f"❌ AI integration test failed: {e}")
        return False

async def test_cli_integration():
    """Test CLI functionality"""
    print("\n⌨️ Testing CLI integration...")
    
    try:
        import subprocess
        import sys
        
        # Test CLI help
        result = subprocess.run([sys.executable, "cli.py", "--help"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0 and "AI-Powered Secure Code Review" in result.stdout:
            print("✅ CLI help working")
        else:
            print("⚠️ CLI help not working properly")
            return False
        
        # Test stats command with examples
        if Path("examples").exists():
            result = subprocess.run([sys.executable, "cli.py", "stats", "--path", "examples"], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ CLI stats command working")
            else:
                print(f"⚠️ CLI stats command failed: {result.stderr}")
        
        return True
        
    except Exception as e:
        print(f"❌ CLI integration test failed: {e}")
        return False

def create_example_files():
    """Create example vulnerable files for testing"""
    print("\n📁 Creating example files...")
    
    examples_dir = Path("examples")
    examples_dir.mkdir(exist_ok=True)
    
    # Create Python example
    (examples_dir / "vulnerable_python.py").write_text(VULNERABLE_PYTHON_CODE)
    
    # Create Go example
    (examples_dir / "vulnerable_go.go").write_text(VULNERABLE_GO_CODE)
    
    # Create Java example
    java_code = '''
public class VulnerableJava {
    private static final String API_KEY = "sk-1234567890abcdef";
    
    public User getUser(String username) {
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return executeQuery(query);
    }
    
    public void executeCommand(String userInput) {
        // Command Injection vulnerability
        Runtime.getRuntime().exec("ls " + userInput);
    }
}
'''
    (examples_dir / "VulnerableJava.java").write_text(java_code)
    
    # Create C# example
    csharp_code = '''
using System;
using System.Data.SqlClient;
using System.Diagnostics;

public class VulnerableCs {
    private const string ApiKey = "sk-1234567890abcdef";
    
    public void GetUser(string username) {
        // SQL Injection vulnerability
        string query = "SELECT * FROM users WHERE username = '" + username + "'";
        using (var connection = new SqlConnection("connectionString")) {
            var command = new SqlCommand(query, connection);
            command.ExecuteQuery();
        }
    }
    
    public void ExecuteCommand(string userInput) {
        // Command Injection vulnerability
        Process.Start("cmd.exe", "/c dir " + userInput);
    }
}
'''
    (examples_dir / "VulnerableCs.cs").write_text(csharp_code)
    
    print("✅ Example files created in examples/ directory")

async def main():
    """Run all tests"""
    print("🚀 Starting AI Secure Code Review CLI Tool Tests\n")
    
    # Create example files
    create_example_files()
    
    # Run tests
    basic_ok = await test_basic_functionality()
    ai_ok = await test_ai_integration()
    cli_ok = await test_cli_integration()
    
    print("\n" + "="*50)
    print("📊 TEST SUMMARY")
    print("="*50)
    print(f"Basic Functionality: {'✅ PASS' if basic_ok else '❌ FAIL'}")
    print(f"AI Integration:      {'✅ PASS' if ai_ok else '❌ FAIL'}")
    print(f"CLI Integration:     {'✅ PASS' if cli_ok else '❌ FAIL'}")
    
    if basic_ok and ai_ok and cli_ok:
        print("\n🎉 All tests passed! Your setup is ready to use.")
        print("\nNext steps:")
        print("1. Try: python cli.py scan --path examples")
        print("2. Generate report: python cli.py scan --path examples --format html --output report.html")
    else:
        print("\n⚠️ Some tests failed. Check the error messages above.")
        print("Make sure you have:")
        print("- Installed all dependencies")
        print("- Set up your API keys in config/.env")
        print("- All required files are present")

if __name__ == "__main__":
    asyncio.run(main())

# ============================================
# Makefile - For easy development commands
# ============================================
"""
.PHONY: install test clean lint format

install:
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	@echo "✅ Installation complete! Run 'source venv/bin/activate' to activate."

test:
	python test_integration.py

test-examples:
	python cli.py scan --path examples --format table

clean:
	rm -rf venv/
	rm -rf __pycache__/
	rm -rf */__pycache__/
	rm -rf .cache/
	find . -name "*.pyc" -delete

lint:
	flake8 --max-line-length=100 --ignore=E203,W503 .
	black --check --line-length=100 .

format:
	black --line-length=100 .
	isort .

setup-dev:
	pip install black isort flake8 pytest
	@echo "✅ Development tools installed"

docker-build:
	docker build -t ai-secure-review .

docker-run:
	docker run -it --rm -v $(PWD):/workspace ai-secure-review

help:
	@echo "Available commands:"
	@echo "  install      - Install dependencies in virtual environment"
	@echo "  test         - Run integration tests"
	@echo "  test-examples- Scan example files"
	@echo "  clean        - Clean up generated files"
	@echo "  lint         - Check code style"
	@echo "  format       - Format code"
	@echo "  setup-dev    - Install development tools"
	@echo "  help         - Show this help message"
"""