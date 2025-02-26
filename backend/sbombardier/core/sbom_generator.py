"""
Core SBOM generation module supporting SPDX and CycloneDX formats.
"""
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import License
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

# Try to import SPDX libraries - make them optional
try:
    # Try importing from newer spdx-tools package first
    try:
        from spdx_tools.spdx.model import Document
        from spdx_tools.spdx.model.license import License as SPDXLicense
        from spdx_tools.spdx.model.document import CreationInfo
        SPDX_AVAILABLE = True
        SPDX_NEW_API = True
    except ImportError:
        # Fall back to older spdx package if available
        from spdx.creationinfo import Tool as SPDXTool
        from spdx.document import Document, License as SPDXLicense
        from spdx.version import Version
        SPDX_AVAILABLE = True
        SPDX_NEW_API = False
except ImportError:
    SPDX_AVAILABLE = False
    # Define placeholders to avoid syntax errors
    SPDXLicense = object
    Document = object
    class Version:
        def __init__(self, *args): pass

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
        self.license_factory = LicenseFactory()
        
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
            # Create component with a unique bom_ref
            component = self._create_component(
                name=dep.name,
                version=dep.version,
                type=dep.type,
                bom_ref=f"{dep.name}@{dep.version}"
            )
            
            # Add sub-dependencies as separate components and register dependencies
            sub_components = []
            for sub_dep in dep.dependencies:
                sub_component = self._create_component(
                    name=sub_dep.name,
                    version=sub_dep.version,
                    type=sub_dep.type,
                    bom_ref=f"{sub_dep.name}@{sub_dep.version}"
                )
                self.components.append(sub_component)
                sub_components.append(sub_component)
                
            self.components.append(component)
        
    def generate_sbom(self) -> str:
        """Generate SBOM document using latest library conventions"""
        bom = Bom()
        
        # Set root component
        root_component = Component(
            name=self.project_path.name,
            version="0.0.0",  # Should get actual version
            type=ComponentType.APPLICATION,
            bom_ref=f"{self.project_path.name}@root"
        )
        bom.metadata.component = root_component
        
        # Add components
        for component in self.components:
            bom.components.add(component)
            
        # Register dependencies
        for component in self.components:
            if hasattr(component, 'dependencies') and component.dependencies:
                bom.register_dependency(component, component.dependencies)
        
        # Get appropriate output format and schema version
        output = make_outputter(
            bom=bom,
            output_format=OutputFormat.JSON if self.format == SBOMFormat.CYCLONEDX else OutputFormat.XML,
            schema_version=SchemaVersion.V1_4  # Use the latest schema version
        )
        
        return output.output_as_string()
        
    def generate_spdx(self) -> Document:
        """Generate SPDX SBOM.
        
        Returns:
            Document: SPDX document
        """
        if not SPDX_AVAILABLE:
            raise ImportError(
                "SPDX libraries are not installed. Please install spdx-tools package: "
                "pip install spdx-tools"
            )
            
        if SPDX_NEW_API:
            # New SPDX API implementation (spdx-tools)
            from spdx_tools.spdx.model.document import Document, CreationInfo
            from spdx_tools.spdx.model.package import Package
            from spdx_tools.spdx.model.version import Version
            
            doc = Document(
                spdx_id="SPDXRef-DOCUMENT",
                name=f"sbombardier-{self.project_path.name}",
                spdx_version="SPDX-2.3",
                data_license="CC0-1.0",
                document_namespace=f"http://spdx.org/spdxdocs/sbombardier-{self.project_path.name}-1.0",
                creation_info=CreationInfo(
                    creators=["Tool: SBOMbardier-0.1.0"],
                    created=None  # This will default to current time
                )
            )
            
            # Convert components to SPDX packages
            for component in self.components:
                package = Package(
                    name=component.name,
                    spdx_id=f"SPDXRef-{component.name}",
                    download_location="NOASSERTION",
                    version=component.version,
                    license_concluded="NOASSERTION"
                )
                
                # Add license if available
                if component.licenses and len(component.licenses) > 0:
                    # Get the first license
                    license_obj = next(iter(component.licenses))
                    if hasattr(license_obj, 'id') and license_obj.id:
                        package.license_concluded = license_obj.id
                
                # Add package to document
                doc.packages = doc.packages + [package]
            
            return doc
        else:
            # Legacy SPDX API implementation
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
                
                if component.licenses and len(component.licenses) > 0:
                    # Get the first license
                    license_obj = next(iter(component.licenses))
                    if hasattr(license_obj, 'id') and license_obj.id:
                        package.license_declared = SPDXLicense.from_identifier(license_obj.id)
                    else:
                        package.license_declared = "NOASSERTION"
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
        
    def _create_component(self, name: str, version: str, type: str, bom_ref: str = None) -> Component:
        """Create a CycloneDX component with proper license handling"""
        # Create a unique bom_ref if not provided
        if bom_ref is None:
            bom_ref = f"{name}@{version}"
            
        # Create component with proper attributes
        component = Component(
            name=name,
            version=version,
            type=ComponentType.LIBRARY,
            bom_ref=bom_ref,
            purl=PackageURL(type=type, name=name, version=version)
        )
        
        return component
    
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
            bom_ref=f"{name}@{version}",
            purl=PackageURL(type=type, name=name, version=version)
        )
        
        # Add license if provided
        if license_id:
            component.licenses.add(self.license_factory.make_license(id=license_id))
            
        # Add supplier if provided
        if supplier:
            component.supplier = OrganizationalEntity(name=supplier)
            
        self.components.append(component)