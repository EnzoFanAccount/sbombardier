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
        """Resolve Maven dependencies using proper DOT parsing."""
        try:
            # Generate dependency tree
            deps_file = self.project_path / "deps.txt"
            cmd = [
                "mvn",
                "dependency:tree",
                "-DoutputType=dot",
                f"-DoutputFile={deps_file}"
            ]
            subprocess.run(cmd, cwd=self.project_path, check=True)

            dependencies = []
            if deps_file.exists():
                from pyparsing import Word, alphas, alphanums, QuotedString, Suppress, OneOrMore
                
                # Define DOT grammar
                node_id = Word(alphas, alphanums + "_.")
                attr = Suppress("=") + QuotedString('"')
                node_stmt = node_id + Suppress("[") + OneOrMore(attr) + Suppress("]")
                edge_stmt = Suppress("->")
                graph_parser = (OneOrMore(node_stmt | edge_stmt))

                # Parse the DOT file
                with open(deps_file) as f:
                    dot_content = f.read()
                    parsed = graph_parser.parseString(dot_content)

                # Build dependency graph
                nodes = {}
                edges = []
                current_node = None
                for item in parsed:
                    if isinstance(item, str) and item == "->":
                        edges.append((current_node, None))
                    elif isinstance(item, str) and current_node:
                        edges.append((current_node, item))
                        current_node = None
                    else:
                        parts = list(item)
                        node_name = parts[0]
                        attributes = {k: v for k, v in zip(parts[1::2], parts[2::2])}
                        nodes[node_name] = attributes
                        current_node = node_name

                # Process Maven coordinates
                def parse_maven_coords(node_id: str) -> dict:
                    parts = node_id.split(":")
                    if len(parts) >= 4:
                        return {
                            "group": parts[0],
                            "artifact": parts[1],
                            "type": parts[2],
                            "version": parts[3],
                            "scope": parts[4] if len(parts) > 4 else "compile"
                        }
                    return None

                # Build dependency hierarchy
                dep_map = {}
                for node_id, attrs in nodes.items():
                    coords = parse_maven_coords(attrs.get("label", node_id))
                    if not coords:
                        continue
                    
                    dep = DependencyInfo(
                        name=f"{coords['group']}:{coords['artifact']}",
                        version=coords['version'],
                        dependencies=[],
                        dev_dependency=coords['scope'] in ["test", "provided"]
                    )
                    dep_map[node_id] = dep

                # Add dependencies based on edges
                for source, target in edges:
                    if source in dep_map and target in dep_map:
                        dep_map[source].dependencies.append(dep_map[target])

                # Find root dependencies (those not appearing as targets)
                all_targets = {target for _, target in edges}
                dependencies = [dep for node_id, dep in dep_map.items() 
                            if node_id not in all_targets]

                deps_file.unlink()  # Clean up

            return dependencies

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to resolve Maven dependencies: {e.stderr}")
        except ImportError:
            raise RuntimeError("DOT parsing requires pyparsing package. Install with: pip install pyparsing")
            
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