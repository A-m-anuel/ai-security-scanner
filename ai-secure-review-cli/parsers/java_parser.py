
import re
from typing import List, Optional
from pathlib import Path

from .base_parser import BaseParser
from core.models import CodeContext, Language

class JavaParser(BaseParser):
    """Parser for Java code using regex patterns"""
    
    def __init__(self):
        super().__init__(Language.JAVA)
    
    def parse_file(self, file_path: str) -> CodeContext:
        """Parse Java file and extract context"""
        
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
        """Extract import statements from Java code"""
        imports = []
        
        # Import pattern: import package.Class;
        import_pattern = r'import\s+(?:static\s+)?([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*(?:\.\*)?)\s*;'
        for match in re.finditer(import_pattern, code):
            imports.append(match.group(1))
        
        return list(set(imports))
    
    def extract_functions(self, code: str) -> List[str]:
        """Extract method names from Java code"""
        functions = []
        
        # Method pattern: [modifiers] returnType methodName(...)
        method_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:\w+\s+)*([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\s*\{'
        for match in re.finditer(method_pattern, code):
            method_name = match.group(1)
            # Filter out common keywords that might be captured
            if method_name not in ['if', 'while', 'for', 'switch', 'try', 'catch', 'synchronized']:
                functions.append(method_name)
        
        return functions
    
    def extract_classes(self, code: str) -> List[str]:
        """Extract class names from Java code"""
        classes = []
        
        # Class pattern: [modifiers] class ClassName
        class_pattern = r'(?:public|private|protected)?\s*(?:abstract|final)?\s*(?:class|interface|enum)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for match in re.finditer(class_pattern, code):
            classes.append(match.group(1))
        
        return classes
    
    def _extract_dependencies(self, file_path: str) -> List[str]:
        """Extract dependencies from pom.xml or build.gradle"""
        dependencies = []
        
        project_root = Path(file_path).parent
        while project_root.parent != project_root:
            # Check for Maven pom.xml
            pom_xml = project_root / 'pom.xml'
            if pom_xml.exists():
                try:
                    with open(pom_xml, 'r') as f:
                        content = f.read()
                        # Simple regex to extract groupId and artifactId
                        dep_pattern = r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>'
                        for match in re.finditer(dep_pattern, content):
                            dependencies.append(f"{match.group(1)}:{match.group(2)}")
                    break
                except Exception:
                    pass
            
            # Check for Gradle build.gradle
            build_gradle = project_root / 'build.gradle'
            if build_gradle.exists():
                try:
                    with open(build_gradle, 'r') as f:
                        content = f.read()
                        # Extract implementation/compile dependencies
                        dep_pattern = r'(?:implementation|compile|api)\s+[\'"]([^\'\"]+)[\'"]'
                        for match in re.finditer(dep_pattern, content):
                            dependencies.append(match.group(1))
                    break
                except Exception:
                    pass
            
            project_root = project_root.parent
        
        return dependencies
    
    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect Java framework being used"""
        framework_patterns = {
            'spring': ['@SpringBootApplication', '@Controller', '@Service', '@Repository', 'springframework'],
            'struts': ['struts', 'ActionSupport', '@Action'],
            'jsf': ['javax.faces', '@ManagedBean', 'FacesContext'],
            'hibernate': ['@Entity', '@Table', 'hibernate', 'SessionFactory'],
            'jersey': ['@Path', '@GET', '@POST', 'jersey'],
            'junit': ['@Test', 'junit', 'Assert']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in code for pattern in patterns):
                return framework
        
        return None
    
    def _detect_database(self, code: str) -> Optional[str]:
        """Detect database technology being used"""
        db_patterns = {
            'mysql': ['mysql', 'com.mysql.jdbc'],
            'postgresql': ['postgresql', 'org.postgresql'],
            'oracle': ['oracle', 'ojdbc'],
            'sqlserver': ['sqlserver', 'com.microsoft.sqlserver'],
            'h2': ['h2database', 'org.h2'],
            'mongodb': ['mongodb', 'com.mongodb'],
            'redis': ['jedis', 'lettuce']
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
