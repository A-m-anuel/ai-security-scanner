# debug_config.py - Run this first to see what's happening
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

print("=== DEBUGGING CONFIG LOADING ===")

# Load environment
env_file = Path("config/.env")
print(f"1. .env file exists: {env_file.exists()}")

if env_file.exists():
    print(f"2. .env file content: {env_file.read_text()}")
    load_dotenv(env_file)
    
    # Check if environment variable is set
    api_key = os.getenv('HUGGINGFACE_API_KEY')
    print(f"3. Environment variable set: {bool(api_key)}")
    if api_key:
        print(f"4. API key value: {api_key}")

# Load YAML config
config_file = Path("config/ai_config.yaml")
print(f"5. Config file exists: {config_file.exists()}")

if config_file.exists():
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    print(f"6. YAML config loaded successfully")
    
    # Check the template
    template = config.get('ai_providers', {}).get('huggingface', {}).get('api_key')
    print(f"7. API key template in YAML: {repr(template)}")
    
    # Check replacement
    if template and template.startswith('${') and template.endswith('}'):
        env_var_name = template[2:-1]
        print(f"8. Environment variable name: {env_var_name}")
        
        actual_value = os.getenv(env_var_name)
        print(f"9. Actual value from environment: {actual_value}")
    else:
        print(f"8. Template doesn't match expected format: {template}")

print("\n=== SOLUTION ===")
print("If step 9 shows None, there's an issue with environment loading.")