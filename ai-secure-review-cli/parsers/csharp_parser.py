
import re
from typing import List, Optional
from pathlib import Path

from .base_parser import BaseParser
from core.models import CodeContext, Language

class CSharpParser(BaseParser):
    """Parser for C# code using regex patterns"""
    
    def __init__(self):
        super().__init__(Language.CSHARP)
    
    def parse_file(self, file_path: str) -> CodeContext:
        """Parse C# file and extract context"""
        
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
            classes=self.extract_classes(code),
            dependencies=self._extract_dependencies(file_path),
            framework=self._detect_framework(code),
            database_type=self._detect_database(code)
        )
        
        return context
    
    def extract_imports(self, code: str) -> List[str]:
        """Extract using statements from C# code"""
        imports = []
        
        # Using pattern: using Namespace;
        using_pattern = r'using\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*;'
        for match in re.finditer(using_pattern, code):
            imports.append(match.group(1))
        
        return list(set(imports))
    
    def extract_functions(self, code: str) -> List[str]:
        """Extract method names from C# code"""
        functions = []
        
        # Method pattern: [attributes] [modifiers] returnType methodName(...)
        method_pattern = r'(?:public|private|protected|internal)?\s*(?:static|virtual|abstract|override)?\s*(?:async\s+)?(?:\w+\s+)*([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?:where\s+[^{]+)?\s*\{'
        for match in re.finditer(method_pattern, code):
            method_name = match.group(1)
            # Filter out common keywords
            if method_name not in ['if', 'while', 'for', 'foreach', 'switch', 'try', 'catch', 'using', 'lock']:
                functions.append(method_name)
        
        return functions
    
    def extract_classes(self, code: str) -> List[str]:
        """Extract class names from C# code"""
        classes = []
        
        # Class pattern: [modifiers] class/interface/struct ClassName
        class_pattern = r'(?:public|private|protected|internal)?\s*(?:abstract|sealed|static|partial)?\s*(?:class|interface|struct|enum)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for match in re.finditer(class_pattern, code):
            classes.append(match.group(1))
        
        return classes
    
    def _extract_dependencies(self, file_path: str) -> List[str]:
        """Extract dependencies from .csproj or packages.config"""
        dependencies = []
        
        project_root = Path(file_path).parent
        while project_root.parent != project_root:
            # Check for .csproj files
            for csproj in project_root.glob('*.csproj'):
                try:
                    with open(csproj, 'r') as f:
                        content = f.read()
                        # Extract PackageReference elements
                        pkg_pattern = r'<PackageReference\s+Include="([^"]+)"'
                        for match in re.finditer(pkg_pattern, content):
                            dependencies.append(match.group(1))
                        
                        # Extract Reference elements (for older format)
                        ref_pattern = r'<Reference\s+Include="([^,"]+)'
                        for match in re.finditer(ref_pattern, content):
                            dependencies.append(match.group(1))
                except Exception:
                    pass
            
            # Check for packages.config
            packages_config = project_root / 'packages.config'
            if packages_config.exists():
                try:
                    with open(packages_config, 'r') as f:
                        content = f.read()
                        pkg_pattern = r'<package\s+id="([^"]+)"'
                        for match in re.finditer(pkg_pattern, content):
                            dependencies.append(match.group(1))
                except Exception:
                    pass
            
            if dependencies:  # Found some dependencies, stop searching
                break
            project_root = project_root.parent
        
        return list(set(dependencies))
    
    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect C# framework being used"""
        framework_patterns = {
            'aspnet': ['System.Web', '[HttpGet]', '[HttpPost]', 'ActionResult', 'Controller'],
            'aspnetcore': ['Microsoft.AspNet', 'app.UseRouting', 'IActionResult', '[ApiController]'],
            'wpf': ['System.Windows', 'Window', 'UserControl', 'Application.xaml'],
            'winforms': ['System.Windows.Forms', 'Form', 'Button', 'Application.Run'],
            'entityframework': ['System.Data.Entity', 'DbContext', 'DbSet', '[Key]'],
            'efcore': ['Microsoft.EntityFrameworkCore', 'DbContext', 'DbSet'],
            'wcf': ['System.ServiceModel', '[ServiceContract]', '[OperationContract]']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in code for pattern in patterns):
                return framework
        
        return None
    
    def _detect_database(self, code: str) -> Optional[str]:
        """Detect database technology being used"""
        db_patterns = {
            'sqlserver': ['System.Data.SqlClient', 'SqlConnection', 'SqlCommand'],
            'mysql': ['MySql.Data', 'MySqlConnection'],
            'postgresql': ['Npgsql', 'NpgsqlConnection'],
            'sqlite': ['System.Data.SQLite', 'SQLiteConnection'],
            'oracle': ['Oracle.DataAccess', 'OracleConnection'],
            'mongodb': ['MongoDB.Driver', 'MongoClient'],
            'redis': ['StackExchange.Redis', 'ConnectionMultiplexer']
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