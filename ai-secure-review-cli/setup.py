# setup.py
from setuptools import setup, find_packages
import os
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = ""
readme_path = this_directory / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding='utf-8')

# Read requirements
requirements_path = this_directory / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="ai-secure-review-cli",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="AI-powered secure code review CLI tool using Hugging Face models",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ai-secure-review-cli",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/ai-secure-review-cli/issues",
        "Source": "https://github.com/yourusername/ai-secure-review-cli",
        "Documentation": "https://github.com/yourusername/ai-secure-review-cli#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "requests>=2.28.0",
        "tree-sitter>=0.20.0",
        "tree-sitter-python>=0.20.0",
        "tree-sitter-go>=0.20.0",
        "tree-sitter-java>=0.20.0",
        "tree-sitter-c-sharp>=0.20.0",
        "click>=8.0.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0.0",
        "python-dotenv>=1.0.0",
        "asyncio-throttle>=1.0.0",
    ],
    extras_require={
        "cache": ["redis>=4.5.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "isort>=5.10.0",
            "mypy>=0.950",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-secure-review=cli:cli",
            "secure-scan=cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": [
            "config/*.yaml",
            "config/*.yml", 
            "examples/*.py",
            "examples/*.go",
            "examples/*.java",
            "examples/*.cs",
            "reports/templates/*.html",
            "reports/templates/*.md",
        ],
    },
    data_files=[
        ("config", ["config/ai_config.yaml"]),
    ],
    zip_safe=False,
    keywords=[
        "security",
        "code-analysis", 
        "vulnerability-detection",
        "static-analysis",
        "ai",
        "huggingface",
        "owasp",
        "cli",
        "python",
        "go",
        "java",
        "csharp",
    ],
    license="MIT",
    platforms=["any"],
)

# Post-installation setup
def post_install():
    """Post-installation setup tasks"""
    import sys
    import subprocess
    
    print("\n🎉 AI Secure Code Review CLI Tool installed successfully!")
    print("=" * 60)
    
    # Check if tree-sitter language packages are available
    try:
        import tree_sitter_python
        import tree_sitter_go  
        import tree_sitter_java
        import tree_sitter_c_sharp
        print("✅ All tree-sitter language parsers installed")
    except ImportError as e:
        print(f"⚠️  Warning: Some tree-sitter parsers missing: {e}")
        print("   Run: pip install tree-sitter-python tree-sitter-go tree-sitter-java tree-sitter-c-sharp")
    
    print("\n📋 Next Steps:")
    print("1. Get a free Hugging Face API key:")
    print("   https://huggingface.co/settings/tokens")
    print("\n2. Set up your API key:")
    print("   ai-secure-review setup")
    print("\n3. Test the installation:")
    print("   ai-secure-review test-ai")
    print("\n4. Scan your code:")
    print("   ai-secure-review scan --path /path/to/your/code")
    print("\n5. For offline scanning (no API key needed):")
    print("   ai-secure-review scan --path /path/to/your/code --pattern-only")
    print("\n📚 Documentation:")
    print("   https://github.com/yourusername/ai-secure-review-cli")
    print("\n🐛 Issues & Support:")
    print("   https://github.com/yourusername/ai-secure-review-cli/issues")

if __name__ == "__main__":
    # If running setup.py directly
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        # This will run after installation
        import atexit
        atexit.register(post_install)