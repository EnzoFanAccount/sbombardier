"""
Core SBOM generation module supporting SPDX and CycloneDX formats.
"""
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import License, LicenseChoice
from cyclonedx.model.organizational_entity import OrganizationalEntity
from cyclonedx.output import OutputFormat, get_instance
from packageurl import PackageURL
from spdx.creationinfo import Tool as SPDXTool
from spdx.document import Document, License
from spdx.version import Version

from ..scanners.dependency_scanner import DependencyScanner, ScannerType, ScanResult
from ..utils.package_manager import PackageManagerResolver, PackageManagerType, DependencyInfo

class SBOMFormat(str, Enum):
    """Supported SBOM formats."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"

class SBOMGenerator:
    """Main SBOM generation class supporting multiple formats and package managers."""
    
    def __init__(self, project_path: Union[str, Path], format: SBOMFormat = SBOMFormat.CYCLONEDX):
        """Initialize SBOM generator.
        
        Args:
            project_path: Path to the project root
            format: Desired SBOM format (SPDX or CycloneDX)
        """
        self.project_path = Path(project_path)
        self.format = format
        self.components: List[Component] = []
        self.scan_results: List[ScanResult] = []
        self.package_manager = PackageManagerResolver(project_path)
        
    def scan_dependencies(self) -> None:
        """Scan project dependencies using Syft, Trivy, and package managers."""
        # Scan with both tools for comprehensive results
        syft_scanner = DependencyScanner(self.project_path, ScannerType.SYFT)
        trivy_scanner = DependencyScanner(self.project_path, ScannerType.TRIVY)
        
        syft_results = syft_scanner.scan()
        trivy_results = trivy_scanner.scan()
        
        # Merge results from scanners
        self.scan_results = syft_scanner.merge_results(syft_results, trivy_results)
        
        # Add dependencies from package managers
        package_managers = self.package_manager.detect_package_managers()
        for pm_type in package_managers:
            try:
                pm_deps = self.package_manager.resolve_dependencies(pm_type)
                self._add_package_manager_deps(pm_deps, pm_type)
            except RuntimeError as e:
                print(f"Warning: Failed to resolve {pm_type} dependencies: {e}")
        
        # Convert scan results to components
        for result in self.scan_results:
            self._add_component(
                name=result.name,
                version=result.version,
                type=result.type,
                supplier=result.supplier,
                license_id=result.license_id
            )
            
    def _add_package_manager_deps(self, deps: List[DependencyInfo], pm_type: PackageManagerType) -> None:
        """Add dependencies from package manager to components.
        
        Args:
            deps: List of dependencies from package manager
            pm_type: Package manager type
        """
        for dep in deps:
            # Create component
            component = self._create_component(
                name=dep.name,
                version=dep.version,
                type=dep.type
            )
            
            # Add sub-dependencies as dependencies
            for sub_dep in dep.dependencies:
                component.dependencies.append(self._create_component(
                    name=sub_dep.name,
                    version=sub_dep.version,
                    type=sub_dep.type
                ))
                
            self.components.append(component)
        
    def generate_sbom(self) -> str:
        """Generate SBOM document using latest library conventions"""
        bom = Bom()
        bom.metadata.component = Component(
            name=self.project_path.name,
            version="0.0.0",  # Should get actual version
            type="application"
        )
        
        # Add components
        for component in self.components:
            bom.components.add(component)
            
        # Get appropriate output format
        output = get_instance(
            bom=bom,
            output_format=OutputFormat.JSON if self.format == SBOMFormat.CYCLONEDX else OutputFormat.XML
        )
        
        return output.output_as_string()
        
    def generate_spdx(self) -> Document:
        """Generate SPDX SBOM.
        
        Returns:
            Document: SPDX document
        """
        doc = Document()
        
        # Set document info
        doc.version = Version(2, 3)
        doc.namespace = f"http://spdx.org/spdxdocs/sbombardier-{self.project_path.name}-1.0"
        doc.name = f"sbombardier-{self.project_path.name}"
        
        # Add creation info
        doc.creation_info.add_creator(SPDXTool("SBOMbardier-0.1.0"))
        doc.creation_info.set_created_now()
        
        # Convert components to SPDX packages
        for component in self.components:
            package = doc.package = doc.Package(component.name)
            package.version = component.version
            package.download_location = component.purl or "NOASSERTION"
            
            if component.licenses:
                package.license_declared = License.from_identifier(str(component.licenses[0]))
            else:
                package.license_declared = "NOASSERTION"
                
            # Add dependencies
            if component.dependencies:
                for dep in component.dependencies:
                    package.add_dependency(dep.name)
                
        return doc
        
    def generate(self) -> Union[str, Document]:
        """Generate SBOM in the specified format.
        
        Returns:
            Union[str, Document]: Generated SBOM in the specified format
        """
        self.scan_dependencies()
        
        if self.format == SBOMFormat.CYCLONEDX:
            return self.generate_sbom()
        else:
            return self.generate_spdx()
            
    def _create_purl(self, name: str, version: str, type: str = "library") -> str:
        """Create Package URL (purl) for a component.
        
        Args:
            name: Package name
            version: Package version
            type: Package type
            
        Returns:
            str: Package URL
        """
        return str(PackageURL(type=type, name=name, version=version))
        
    def _add_component(self, 
                      name: str,
                      version: str,
                      type: str = "library",
                      supplier: Optional[str] = None,
                      license_id: Optional[str] = None) -> None:
        """Add a component to the SBOM."""
        component = Component(
            name=name,
            version=version,
            type=ComponentType.LIBRARY,
            licenses=[LicenseChoice(license=License(id=license_id))] if license_id else None,
            supplier=OrganizationalEntity(name=supplier) if supplier else None,
            purl=PackageURL(type=type, name=name, version=version)
        )
        self.components.append(component)

    def _create_component(self, name: str, version: str, type: str) -> Component:
        """Create a CycloneDX component with proper license handling"""
        licenses = []
        if self.license_id:
            licenses.append(LicenseChoice(license=License(id=self.license_id)))
            
        return Component(
            name=name,
            version=version,
            type=ComponentType.LIBRARY,
            licenses=licenses,
            supplier=OrganizationalEntity(name=self.supplier) if self.supplier else None,
            purl=self.purl
        ) 