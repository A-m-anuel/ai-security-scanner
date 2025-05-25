# parsers/python_parser.py
import ast
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base_parser import BaseParser
from core.models import CodeContext, Language

class PythonParser(BaseParser):
    """Parser for Python code using AST"""
    
    def __init__(self):
        super().__init__(Language.PYTHON)
    
    def parse_file(self, file_path: str) -> CodeContext:
        """Parse Python file and extract context"""
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return self._empty_context(file_path)
        
        try:
            tree = ast.parse(code)
            
            context = CodeContext(
                file_path=file_path,
                language=self.language,
                imports=self.extract_imports(code),
                functions=self.extract_functions(code),
                classes=self.extract_classes(code),
                dependencies=self._extract_dependencies(file_path),
                framework=self._detect_framework(code),
                database_type=self._detect_database(code)
            )
            
            return context
            
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
            return self._empty_context(file_path)
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return self._empty_context(file_path)
    
    def extract_imports(self, code: str) -> List[str]:
        """Extract import statements from Python code"""
        imports = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
                        
        except Exception:
            # Fallback to regex
            import_patterns = [
                r'^\s*import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)',
                r'^\s*from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+import'
            ]
            
            for line in code.split('\n'):
                for pattern in import_patterns:
                    match = re.match(pattern, line)
                    if match:
                        imports.append(match.group(1))
        
        return list(set(imports))  # Remove duplicates
    
    def extract_functions(self, code: str) -> List[str]:
        """Extract function names from Python code"""
        functions = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.AsyncFunctionDef):
                    functions.append(node.name)
                    
        except Exception:
            # Fallback to regex
            func_pattern = r'^\s*(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            for line in code.split('\n'):
                match = re.match(func_pattern, line)
                if match:
                    functions.append(match.group(1))
        
        return functions
    
    def extract_classes(self, code: str) -> List[str]:
        """Extract class names from Python code"""
        classes = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                    
        except Exception:
            # Fallback to regex
            class_pattern = r'^\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(.*\))?\s*:'
            for line in code.split('\n'):
                match = re.match(class_pattern, line)
                if match:
                    classes.append(match.group(1))
        
        return classes
    
    def _extract_dependencies(self, file_path: str) -> List[str]:
        """Extract dependencies from requirements.txt or setup.py"""
        dependencies = []
        
        # Look for requirements.txt
        project_root = Path(file_path).parent
        while project_root.parent != project_root:
            req_file = project_root / 'requirements.txt'
            if req_file.exists():
                try:
                    with open(req_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Extract package name (before ==, >=, etc.)
                                pkg_name = re.split(r'[><=!]', line)[0].strip()
                                dependencies.append(pkg_name)
                    break
                except Exception:
                    pass
            project_root = project_root.parent
        
        return dependencies
    
    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect Python framework being used"""
        framework_patterns = {
            'django': ['from django', 'import django', 'Django'],
            'flask': ['from flask', 'import flask', 'Flask'],
            'fastapi': ['from fastapi', 'import fastapi', 'FastAPI'],
            'tornado': ['from tornado', 'import tornado'],
            'bottle': ['from bottle', 'import bottle'],
            'pyramid': ['from pyramid', 'import pyramid']
        }
        
        code_lower = code.lower()
        for framework, patterns in framework_patterns.items():
            if any(pattern.lower() in code_lower for pattern in patterns):
                return framework
        
        return None
    
    def _detect_database(self, code: str) -> Optional[str]:
        """Detect database technology being used"""
        db_patterns = {
            'postgresql': ['psycopg2', 'postgresql', 'postgres'],
            'mysql': ['pymysql', 'mysqlclient', 'mysql.connector'],
            'sqlite': ['sqlite3', 'sqlite'],
            'mongodb': ['pymongo', 'mongodb'],
            'redis': ['redis', 'Redis'],
            'sqlalchemy': ['sqlalchemy', 'SQLAlchemy']
        }
        
        code_lower = code.lower()
        for db, patterns in db_patterns.items():
            if any(pattern.lower() in code_lower for pattern in patterns):
                return db
        
        return None
    
    def _empty_context(self, file_path: str) -> CodeContext:
        """Return empty context for files that can't be parsed"""
        return CodeContext(
            file_path=file_path,
            language=self.language,
            imports=[],
            functions=[],
            classes=[],
            dependencies=[]
        )
