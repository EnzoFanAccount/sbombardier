"""
Package manager integration utilities for resolving transitive dependencies.
"""
import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

import pkg_resources
from packageurl import PackageURL

class PackageManagerType(str, Enum):
    """Supported package manager types."""
    PIP = "pip"
    NPM = "npm"
    MAVEN = "maven"
    GRADLE = "gradle"

@dataclass
class DependencyInfo:
    """Information about a package dependency."""
    name: str
    version: str
    dependencies: List['DependencyInfo']
    dev_dependency: bool = False

class PackageManagerResolver:
    """Resolver for package manager dependencies."""
    
    def __init__(self, project_path: Union[str, Path]):
        """Initialize package manager resolver.
        
        Args:
            project_path: Path to project root
        """
        self.project_path = Path(project_path)
        
    def detect_package_managers(self) -> List[PackageManagerType]:
        """Detect package managers used in the project.
        
        Returns:
            List[PackageManagerType]: List of detected package managers
        """
        package_managers = []
        
        if (self.project_path / "requirements.txt").exists() or (self.project_path / "setup.py").exists():
            package_managers.append(PackageManagerType.PIP)
            
        if (self.project_path / "package.json").exists():
            package_managers.append(PackageManagerType.NPM)
            
        if (self.project_path / "pom.xml").exists():
            package_managers.append(PackageManagerType.MAVEN)
            
        if (self.project_path / "build.gradle").exists() or (self.project_path / "build.gradle.kts").exists():
            package_managers.append(PackageManagerType.GRADLE)
            
        return package_managers
        
    def resolve_dependencies(self, package_manager: PackageManagerType) -> List[DependencyInfo]:
        """Resolve dependencies for a specific package manager.
        
        Args:
            package_manager: Package manager to resolve dependencies for
            
        Returns:
            List[DependencyInfo]: List of resolved dependencies
        """
        if package_manager == PackageManagerType.PIP:
            return self._resolve_pip_dependencies()
        elif package_manager == PackageManagerType.NPM:
            return self._resolve_npm_dependencies()
        elif package_manager == PackageManagerType.MAVEN:
            return self._resolve_maven_dependencies()
        else:
            return self._resolve_gradle_dependencies()
            
    def _resolve_pip_dependencies(self) -> List[DependencyInfo]:
        """Resolve Python package dependencies.
        
        Returns:
            List[DependencyInfo]: List of resolved Python dependencies
        """
        try:
            # Use pip to list installed packages
            cmd = ["pip", "list", "--format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            packages = json.loads(result.stdout)
            
            dependencies = []
            for pkg in packages:
                # Get package dependencies
                dist = pkg_resources.get_distribution(pkg["name"])
                deps = [
                    DependencyInfo(
                        name=dep.name,
                        version=dep.version,
                        dependencies=[]
                    )
                    for dep in dist.requires()
                ]
                
                dependencies.append(DependencyInfo(
                    name=pkg["name"],
                    version=pkg["version"],
                    dependencies=deps
                ))
                
            return dependencies
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to resolve pip dependencies: {e.stderr}")
            
    def _resolve_npm_dependencies(self) -> List[DependencyInfo]:
        """Resolve Node.js package dependencies.
        
        Returns:
            List[DependencyInfo]: List of resolved Node.js dependencies
        """
        try:
            # Use npm list in JSON format
            cmd = ["npm", "list", "--json"]
            result = subprocess.run(cmd, cwd=self.project_path, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            def process_dependencies(deps_dict: Dict) -> List[DependencyInfo]:
                """Process npm dependency tree recursively."""
                deps = []
                for name, info in deps_dict.items():
                    deps.append(DependencyInfo(
                        name=name,
                        version=info.get("version", ""),
                        dependencies=process_dependencies(info.get("dependencies", {})),
                        dev_dependency=info.get("dev", False)
                    ))
                return deps
                
            return process_dependencies(data.get("dependencies", {}))
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to resolve npm dependencies: {e.stderr}")
            
    def _resolve_maven_dependencies(self) -> List[DependencyInfo]:
        """Resolve Maven dependencies.
        
        Returns:
            List[DependencyInfo]: List of resolved Maven dependencies
        """
        try:
            # Use Maven dependency plugin to list dependencies
            cmd = [
                "mvn",
                "dependency:tree",
                "-DoutputType=dot",
                "-DoutputFile=deps.txt"
            ]
            subprocess.run(cmd, cwd=self.project_path, check=True)
            
            # Parse dependency tree from generated file
            deps_file = self.project_path / "deps.txt"
            dependencies = []
            
            if deps_file.exists():
                # Parse DOT format dependency tree
                # This is a simplified parser - in practice you'd want to use a proper DOT parser
                with open(deps_file) as f:
                    for line in f:
                        if "->" in line:
                            # Parse dependency relationship
                            src, dst = line.split("->")
                            src = src.strip().strip('"')
                            dst = dst.strip().strip('"')
                            
                            # Extract name and version
                            src_parts = src.split(":")
                            if len(src_parts) >= 2:
                                dependencies.append(DependencyInfo(
                                    name=src_parts[1],
                                    version=src_parts.get(3, ""),
                                    dependencies=[]
                                ))
                                
                deps_file.unlink()  # Clean up
                
            return dependencies
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to resolve Maven dependencies: {e.stderr}")
            
    def _resolve_gradle_dependencies(self) -> List[DependencyInfo]:
        """Resolve Gradle dependencies.
        
        Returns:
            List[DependencyInfo]: List of resolved Gradle dependencies
        """
        try:
            # Use Gradle dependencies task
            cmd = ["gradle", "dependencies", "--console=plain"]
            result = subprocess.run(cmd, cwd=self.project_path, capture_output=True, text=True, check=True)
            
            dependencies = []
            current_config = None
            
            # Parse Gradle dependency output
            for line in result.stdout.splitlines():
                if line.endswith("dependencies"):
                    current_config = line.split(" ")[0]
                elif line.strip().startswith("+---") or line.strip().startswith("\\---"):
                    # Parse dependency line
                    parts = line.split(":")
                    if len(parts) >= 2:
                        name = parts[1].strip()
                        version = parts[2].strip() if len(parts) > 2 else ""
                        
                        dependencies.append(DependencyInfo(
                            name=name,
                            version=version,
                            dependencies=[],
                            dev_dependency=current_config in ["testImplementation", "testCompile"]
                        ))
                        
            return dependencies
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to resolve Gradle dependencies: {e.stderr}")
            
    def create_purl(self, dep: DependencyInfo, pkg_type: PackageManagerType) -> str:
        """Create Package URL for a dependency.
        
        Args:
            dep: Dependency information
            pkg_type: Package manager type
            
        Returns:
            str: Package URL
        """
        type_map = {
            PackageManagerType.PIP: "pypi",
            PackageManagerType.NPM: "npm",
            PackageManagerType.MAVEN: "maven",
            PackageManagerType.GRADLE: "maven"
        }
        
        return str(PackageURL(
            type=type_map[pkg_type],
            name=dep.name,
            version=dep.version
        )) 