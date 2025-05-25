# core/context_builder.py
from typing import Dict, Any, List, Optional
from pathlib import Path
import os
import re

class ContextBuilder:
    """Builds comprehensive context for AI analysis"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
    
    def build_project_context(self) -> Dict[str, Any]:
        """Build overall project context"""
        
        context = {
            'project_structure': self._analyze_project_structure(),
            'dependencies': self._extract_all_dependencies(),
            'config_files': self._find_config_files(),
            'frameworks': self._detect_frameworks(),
            'databases': self._detect_databases(),
            'security_configs': self._find_security_configs()
        }
        
        return context
    
    def _analyze_project_structure(self) -> Dict[str, Any]:
        """Analyze project directory structure"""
        
        structure = {
            'directories': [],
            'file_types': {},
            'depth': 0
        }
        
        for root, dirs, files in os.walk(self.project_root):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if not self._should_ignore_dir(d)]
            
            rel_root = os.path.relpath(root, self.project_root)
            if rel_root != '.':
                structure['directories'].append(rel_root)
                structure['depth'] = max(structure['depth'], rel_root.count(os.sep))
            
            for file in files:
                ext = Path(file).suffix.lower()
                structure['file_types'][ext] = structure['file_types'].get(ext, 0) + 1
        
        return structure
    
    def _extract_all_dependencies(self) -> Dict[str, List[str]]:
        """Extract dependencies from various dependency files"""
        
        dependencies = {
            'python': [],
            'go': [],
            'java': [],
            'csharp': [],
            'javascript': []
        }
        
        # Python dependencies
        req_files = ['requirements.txt', 'requirements-dev.txt', 'pyproject.toml', 'setup.py']
        for req_file in req_files:
            req_path = self.project_root / req_file
            if req_path.exists():
                dependencies['python'].extend(self._parse_python_deps(req_path))
        
        # Go dependencies
        go_mod = self.project_root / 'go.mod'
        if go_mod.exists():
            dependencies['go'] = self._parse_go_deps(go_mod)
        
        # Java dependencies
        pom_xml = self.project_root / 'pom.xml'
        if pom_xml.exists():
            dependencies['java'] = self._parse_maven_deps(pom_xml)
        
        # C# dependencies
        for csproj in self.project_root.glob('*.csproj'):
            dependencies['csharp'].extend(self._parse_csharp_deps(csproj))
        
        return dependencies
    
    def _find_config_files(self) -> List[str]:
        """Find configuration files that might contain security settings"""
        
        config_patterns = [
            '*.yml', '*.yaml', '*.json', '*.ini', '*.cfg', '*.conf',
            '.env*', 'docker-compose*', 'Dockerfile*',
            'nginx.conf', 'apache*.conf'
        ]
        
        config_files = []
        for pattern in config_patterns:
            config_files.extend([str(f) for f in self.project_root.rglob(pattern)])
        
        return config_files
    
    def _detect_frameworks(self) -> List[str]:
        """Detect frameworks used in the project"""
        
        frameworks = set()
        
        # Check for common framework indicators
        framework_indicators = {
            'django': ['manage.py', 'settings.py', 'wsgi.py'],
            'flask': ['app.py', 'run.py'],
            'spring': ['pom.xml', 'application.properties'],
            'dotnet': ['*.csproj', 'Program.cs', 'Startup.cs'],
            'express': ['package.json', 'app.js', 'server.js'],
            'gin': ['go.mod', 'main.go']
        }
        
        for framework, indicators in framework_indicators.items():
            if any(list(self.project_root.rglob(indicator)) for indicator in indicators):
                frameworks.add(framework)
        
        return list(frameworks)
    
    def _detect_databases(self) -> List[str]:
        """Detect database technologies used"""
        
        databases = set()
        
        # Check dependency files and config files for database indicators
        db_indicators = {
            'postgresql': ['psycopg2', 'postgresql', 'postgres'],
            'mysql': ['mysql', 'pymysql', 'mariadb'],
            'sqlite': ['sqlite3', 'sqlite'],
            'mongodb': ['mongodb', 'pymongo', 'mongoose'],
            'redis': ['redis', 'ioredis'],
            'oracle': ['oracle', 'cx_Oracle'],
            'sqlserver': ['sqlserver', 'pyodbc', 'mssql']
        }
        
        # Check all text files for database mentions
        for text_file in self.project_root.rglob('*'):
            if text_file.is_file() and text_file.suffix in ['.txt', '.py', '.go', '.java', '.cs', '.js', '.json', '.yml', '.yaml']:
                try:
                    with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        for db, indicators in db_indicators.items():
                            if any(indicator in content for indicator in indicators):
                                databases.add(db)
                except Exception:
                    continue
        
        return list(databases)
    
    def _find_security_configs(self) -> Dict[str, List[str]]:
        """Find security-related configuration files"""
        
        security_configs = {
            'ssl_certs': [],
            'auth_configs': [],
            'security_policies': []
        }
        
        # SSL/TLS certificates and keys
        cert_patterns = ['*.pem', '*.crt', '*.key', '*.p12', '*.pfx']
        for pattern in cert_patterns:
            security_configs['ssl_certs'].extend([str(f) for f in self.project_root.rglob(pattern)])
        
        # Authentication configs
        auth_files = ['auth.yml', 'oauth.json', 'jwt.config', '.htpasswd']
        for auth_file in auth_files:
            matches = list(self.project_root.rglob(auth_file))
            security_configs['auth_configs'].extend([str(f) for f in matches])
        
        return security_configs
    
    def _should_ignore_dir(self, dirname: str) -> bool:
        """Check if directory should be ignored"""
        ignore_dirs = {
            '.git', '.svn', '__pycache__', 'node_modules', 'vendor',
            '.venv', 'venv', 'env', 'build', 'dist', 'target',
            '.idea', '.vscode', 'bin', 'obj'
        }
        return dirname in ignore_dirs
    
    def _parse_python_deps(self, req_file: Path) -> List[str]:
        """Parse Python dependency file"""
        deps = []
        try:
            with open(req_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract package name
                        pkg_name = re.split(r'[><=!]', line)[0].strip()
                        deps.append(pkg_name)
        except Exception:
            pass
        return deps
    
    def _parse_go_deps(self, go_mod: Path) -> List[str]:
        """Parse Go module dependencies"""
        deps = []
        try:
            with open(go_mod, 'r') as f:
                content = f.read()
                # Simple regex to extract require statements
                require_pattern = r'require\s+([^\s]+)'
                for match in re.finditer(require_pattern, content):
                    deps.append(match.group(1))
        except Exception:
            pass
        return deps
    
    def _parse_maven_deps(self, pom_xml: Path) -> List[str]:
        """Parse Maven dependencies (simplified)"""
        deps = []
        try:
            with open(pom_xml, 'r') as f:
                content = f.read()
                # Simple regex to extract groupId and artifactId
                dep_pattern = r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>'
                for match in re.finditer(dep_pattern, content):
                    deps.append(f"{match.group(1)}:{match.group(2)}")
        except Exception:
            pass
        return deps
    
    def _parse_csharp_deps(self, csproj: Path) -> List[str]:
        """Parse C# project dependencies"""
        deps = []
        try:
            with open(csproj, 'r') as f:
                content = f.read()
                # Extract PackageReference elements
                pkg_pattern = r'<PackageReference\s+Include="([^"]+)"'
                for match in re.finditer(pkg_pattern, content):
                    deps.append(match.group(1))
        except Exception:
            pass
        return deps