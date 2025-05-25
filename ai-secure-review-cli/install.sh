# ============================================
# install.sh - Installation script
# ============================================
"""
#!/bin/bash

echo "🔧 Setting up AI Secure Code Review CLI Tool..."

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if (( $(echo "$python_version < 3.8" | bc -l) )); then
    echo "❌ Python 3.8+ required. Current version: $python_version"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install tree-sitter languages
echo "🌳 Setting up tree-sitter parsers..."
python -c "
import tree_sitter_python
import tree_sitter_go
import tree_sitter_java
import tree_sitter_c_sharp
print('Tree-sitter parsers installed successfully!')
"

# Create config directory and copy example configs
echo "⚙️ Setting up configuration..."
mkdir -p config
cp config/ai_config.yaml.example config/ai_config.yaml 2>/dev/null || true
cp config/.env.example config/.env 2>/dev/null || true

echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit config/.env with your API keys"
echo "2. Run: source venv/bin/activate"
echo "3. Test: python cli.py test-ai"
echo "4. Scan: python cli.py scan --path /path/to/your/code"
"""
