"""
Dependency scanner module integrating with Syft and Trivy.
"""
import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from packageurl import PackageURL

@dataclass
class ScanResult:
    """Result of dependency scanning."""
    name: str
    version: str
    type: str
    supplier: Optional[str]
    license_id: Optional[str]
    purl: Optional[str]

class ScannerType(str, Enum):
    """Supported scanner types."""
    SYFT = "syft"
    TRIVY = "trivy"

class DependencyScanner:
    """Scanner for project dependencies using Syft and Trivy."""
    
    def __init__(self, project_path: Union[str, Path], scanner_type: ScannerType = ScannerType.SYFT):
        """Initialize dependency scanner.
        
        Args:
            project_path: Path to project root
            scanner_type: Scanner to use (Syft or Trivy)
        """
        self.project_path = Path(project_path)
        self.scanner_type = scanner_type
        
    def scan(self) -> List[ScanResult]:
        """Scan project dependencies.
        
        Returns:
            List[ScanResult]: List of discovered dependencies
        """
        if self.scanner_type == ScannerType.SYFT:
            return self._scan_with_syft()
        else:
            return self._scan_with_trivy()
            
    def _scan_with_syft(self) -> List[ScanResult]:
        """Scan dependencies using Syft.
        
        Returns:
            List[ScanResult]: List of discovered dependencies
        """
        try:
            # Run Syft in JSON output mode
            cmd = [
                "syft",
                str(self.project_path),
                "-o",
                "json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            dependencies = []
            for artifact in data.get("artifacts", []):
                dependencies.append(ScanResult(
                    name=artifact.get("name"),
                    version=artifact.get("version"),
                    type=artifact.get("type", "library"),
                    supplier=None,  # Syft doesn't provide supplier info
                    license_id=artifact.get("licenses", [None])[0],
                    purl=artifact.get("purl")
                ))
                
            return dependencies
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Syft scan failed: {e.stderr}")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Syft output")
            
    def _scan_with_trivy(self) -> List[ScanResult]:
        """Scan dependencies using Trivy.
        
        Returns:
            List[ScanResult]: List of discovered dependencies
        """
        try:
            # Run Trivy in JSON output mode
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                str(self.project_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            dependencies = []
            for result in data.get("Results", []):
                for pkg in result.get("Packages", []):
                    dependencies.append(ScanResult(
                        name=pkg.get("Name"),
                        version=pkg.get("Version"),
                        type=pkg.get("Type", "library"),
                        supplier=None,  # Trivy doesn't provide supplier info
                        license_id=pkg.get("License"),
                        purl=pkg.get("PURL")
                    ))
                    
            return dependencies
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Trivy scan failed: {e.stderr}")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Trivy output")
            
    def merge_results(self, syft_results: List[ScanResult], trivy_results: List[ScanResult]) -> List[ScanResult]:
        """Merge results from both scanners, removing duplicates and combining metadata.
        
        Args:
            syft_results: Results from Syft scan
            trivy_results: Results from Trivy scan
            
        Returns:
            List[ScanResult]: Merged scan results
        """
        # Use dictionary to track unique components by purl
        merged = {}
        
        # Process Syft results first
        for result in syft_results:
            if result.purl:
                merged[result.purl] = result
                
        # Add/update with Trivy results
        for result in trivy_results:
            if result.purl:
                if result.purl in merged:
                    # Update existing entry with any additional info
                    existing = merged[result.purl]
                    if not existing.license_id and result.license_id:
                        existing.license_id = result.license_id
                else:
                    merged[result.purl] = result
                    
        return list(merged.values()) 