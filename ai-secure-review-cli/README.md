
# ============================================
# README.md
# ============================================
"""
# 🔒 AI-Powered Secure Code Review CLI Tool

An intelligent command-line tool that leverages AI models to perform comprehensive security analysis of source code across multiple programming languages.

## ✨ Features

- **Multi-Language Support**: Python, Go, Java, C#
- **AI-Powered Analysis**: Uses OpenAI GPT, Anthropic Claude, or local Ollama models
- **OWASP Top 10 Mapping**: Automatically maps vulnerabilities to OWASP categories
- **Multiple Output Formats**: Console, JSON, HTML, Markdown reports
- **Intelligent Context**: Understands project structure, dependencies, and frameworks
- **Fix Suggestions**: AI-generated remediation code
- **Caching**: Avoid re-analyzing unchanged code
- **Parallel Processing**: Efficient scanning of large codebases

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ai-secure-review-cli.git
cd ai-secure-review-cli

# Run installation script
chmod +x install.sh
./install.sh

# Or install manually
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

1. Copy the example configuration:
```bash
cp config/.env.example config/.env
```

2. Add your AI provider API keys to `config/.env`:
```bash
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

3. Test your configuration:
```bash
python cli.py test-ai --provider openai
```

### Usage Examples

```bash
# Basic scan with OpenAI
python cli.py scan --path ./myproject

# Scan with specific AI provider and model
python cli.py scan --path ./myproject --ai-provider anthropic --model claude-3-sonnet

# Generate HTML report with fix suggestions
python cli.py scan --path ./myproject --format html --output report.html --include-fixes

# Scan only specific languages
python cli.py scan --path ./myproject --languages python,go

# Scan with custom severity threshold
python cli.py scan --path ./myproject --severity high

# Show project statistics
python cli.py stats --path ./myproject

# Clear analysis cache
python cli.py clear-cache
```

## 🛡️ Supported Vulnerabilities

The tool detects vulnerabilities mapped to **OWASP Top 10 2021**:

- **A01:2021** - Broken Access Control
- **A02:2021** - Cryptographic Failures  
- **A03:2021** - Injection (SQL, Command, etc.)
- **A04:2021** - Insecure Design
- **A05:2021** - Security Misconfiguration
- **A06:2021** - Vulnerable and Outdated Components
- **A07:2021** - Identification and Authentication Failures
- **A08:2021** - Software and Data Integrity Failures
- **A09:2021** - Security Logging and Monitoring Failures
- **A10:2021** - Server-Side Request Forgery (SSRF)

## 🔧 Configuration

### AI Providers

Configure multiple AI providers in `config/ai_config.yaml`:

```yaml
ai_providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    model: "gpt-4"
    max_tokens: 2000
    
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    model: "claude-3-sonnet-20240229"
    
  ollama:
    base_url: "http://localhost:11434"
    model: "codellama:13b"
```

### Security Profiles

Choose from different analysis profiles:

- **strict**: Detect all potential issues (Low+ severity)
- **standard**: Focus on likely vulnerabilities (Medium+ severity)  
- **production**: Only critical issues (High+ severity)

## 📊 Report Formats

### Console Output
Rich, colored console output with tables and detailed vulnerability information.

### JSON Report
```bash
python cli.py scan --path ./myproject --format json --output results.json
```

### HTML Report
```bash
python cli.py scan --path ./myproject --format html --output report.html
```

### Markdown Report
```bash
python cli.py scan --path ./myproject --format markdown --output report.md
```

## 🎯 Exit Codes

- `0`: No critical or high severity vulnerabilities
- `1`: High severity vulnerabilities found
- `2`: Critical vulnerabilities found

Perfect for CI/CD integration!

## 🤖 AI Models

### Supported Providers

1. **OpenAI**: GPT-4, GPT-3.5-turbo
2. **Anthropic**: Claude-3 Sonnet, Claude-3 Opus
3. **Ollama**: Local models like CodeLlama, StarCoder

### Token Usage

The tool tracks and reports token usage:
- Estimates costs for cloud providers
- Optimizes requests through intelligent code chunking
- Caches results to minimize API calls

## 🛠️ Development

### Project Structure

```
ai-secure-review-cli/
├── core/                 # Core analysis engine
├── ai_models/           # AI provider implementations  
├── parsers/             # Language parsers
├── reports/             # Report generators
├── utils/               # Utilities (caching, rate limiting)
├── config/              # Configuration files
└── examples/            # Example vulnerable code
```

### Adding New Languages

1. Create parser in `parsers/new_language_parser.py`
2. Add to `parsers/parser_factory.py`
3. Update `core/language_detector.py`
4. Add language-specific prompts

### Adding New AI Providers

1. Implement `ai_models/new_provider_analyzer.py`
2. Extend `AIModelInterface`
3. Add configuration to `config/ai_config.yaml`
4. Update `core/ai_analyzer.py`

## 🔍 How It Works

1. **Language Detection**: Automatically detects programming languages from file extensions
2. **Code Parsing**: Uses tree-sitter for accurate syntax parsing and context extraction
3. **AI Analysis**: Sends code chunks with context to AI models for vulnerability detection
4. **OWASP Mapping**: Maps found issues to OWASP Top 10 categories
5. **Report Generation**: Creates comprehensive reports in multiple formats

## 💡 Best Practices

### For Accurate Results

- Keep your AI provider API keys secure
- Use appropriate security profiles for your use case
- Review AI-generated fix suggestions before applying
- Combine with other security tools for comprehensive coverage

### For Performance

- Use caching to avoid re-analyzing unchanged code
- Adjust parallel processing based on API rate limits
- Consider using local models (Ollama) for sensitive code

## 🚨 Security Considerations

- **API Keys**: Store securely, never commit to version control
- **Sensitive Code**: Consider local models for proprietary code
- **False Positives**: AI may flag non-issues - review findings
- **Rate Limits**: Configure appropriate request rates

## 📈 Roadmap

- [ ] Support for more languages (Rust, JavaScript, TypeScript)
- [ ] Integration with CI/CD platforms (GitHub Actions, GitLab CI)
- [ ] Custom rule creation interface
- [ ] Team collaboration features
- [ ] Advanced dependency vulnerability scanning
- [ ] SARIF output format support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- OpenAI for GPT models
- Anthropic for Claude models
- Tree-sitter for parsing capabilities
- OWASP for security guidelines

---

**⚠️ Disclaimer**: This tool uses AI for vulnerability detection. Results should be reviewed by security professionals. Not all vulnerabilities may be detected, and false positives may occur.
"""