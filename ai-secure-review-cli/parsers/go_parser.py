
import re
from typing import List, Optional
from pathlib import Path

from .base_parser import BaseParser
from core.models import CodeContext, Language

class GoParser(BaseParser):
    """Parser for Go code using regex patterns"""
    
    def __init__(self):
        super().__init__(Language.GO)
    
    def parse_file(self, file_path: str) -> CodeContext:
        """Parse Go file and extract context"""
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return self._empty_context(file_path)
        
        context = CodeContext(
            file_path=file_path,
            language=self.language,
            imports=self.extract_imports(code),
            functions=self.extract_functions(code),
            classes=self.extract_classes(code),  # Go has structs, not classes
            dependencies=self._extract_dependencies(file_path),
            framework=self._detect_framework(code),
            database_type=self._detect_database(code)
        )
        
        return context
    
    def extract_imports(self, code: str) -> List[str]:
        """Extract import statements from Go code"""
        imports = []
        
        # Single import pattern
        single_import = r'import\s+"([^"]+)"'
        for match in re.finditer(single_import, code):
            imports.append(match.group(1))
        
        # Multi-import pattern
        multi_import = r'import\s*\(\s*(.*?)\s*\)'
        for match in re.finditer(multi_import, code, re.DOTALL):
            import_block = match.group(1)
            for line in import_block.split('\n'):
                line = line.strip()
                if line and line.startswith('"') and line.endswith('"'):
                    imports.append(line[1:-1])
                elif '"' in line:
                    # Handle cases like: alias "package"
                    parts = line.split('"')
                    if len(parts) >= 2:
                        imports.append(parts[1])
        
        return list(set(imports))
    
    def extract_functions(self, code: str) -> List[str]:
        """Extract function names from Go code"""
        functions = []
        
        # Function pattern: func name(...) ... {
        func_pattern = r'func\s+(?:\([^)]*\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(func_pattern, code):
            functions.append(match.group(1))
        
        return functions
    
    def extract_classes(self, code: str) -> List[str]:
        """Extract struct names from Go code (Go doesn't have classes)"""
        structs = []
        
        # Struct pattern: type Name struct {
        struct_pattern = r'type\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+struct\s*\{'
        for match in re.finditer(struct_pattern, code):
            structs.append(match.group(1))
        
        return structs
    
    def _extract_dependencies(self, file_path: str) -> List[str]:
        """Extract dependencies from go.mod file"""
        dependencies = []
        
        # Look for go.mod
        project_root = Path(file_path).parent
        while project_root.parent != project_root:
            go_mod = project_root / 'go.mod'
            if go_mod.exists():
                try:
                    with open(go_mod, 'r') as f:
                        content = f.read()
                        # Extract require statements
                        require_pattern = r'require\s+([^\s]+)'
                        for match in re.finditer(require_pattern, content):
                            dependencies.append(match.group(1))
                    break
                except Exception:
                    pass
            project_root = project_root.parent
        
        return dependencies
    
    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect Go framework being used"""
        framework_patterns = {
            'gin': ['gin-gonic/gin', 'gin.'],
            'echo': ['labstack/echo', 'echo.'],
            'fiber': ['gofiber/fiber', 'fiber.'],
            'gorilla': ['gorilla/mux', 'mux.'],
            'buffalo': ['gobuffalo/buffalo']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in code for pattern in patterns):
                return framework
        
        return None
    
    def _detect_database(self, code: str) -> Optional[str]:
        """Detect database technology being used"""
        db_patterns = {
            'postgresql': ['lib/pq', 'postgres'],
            'mysql': ['mysql', 'go-sql-driver'],
            'sqlite': ['sqlite3', 'sqlite'],
            'mongodb': ['mongo-driver', 'mongodb'],
            'redis': ['go-redis', 'redis'],
            'gorm': ['gorm.io/gorm']
        }
        
        for db, patterns in db_patterns.items():
            if any(pattern in code for pattern in patterns):
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