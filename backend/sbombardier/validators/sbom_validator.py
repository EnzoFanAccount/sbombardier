"""
SBOM validation module supporting NTIA and CISA standards.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Union

from cyclonedx.model import Component
from spdx.document import Document

class ValidationStandard(str, Enum):
    """Supported validation standards."""
    NTIA = "ntia"
    CISA = "cisa"
    
@dataclass
class ValidationResult:
    """Result of SBOM validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    
class SBOMValidator:
    """SBOM validator supporting multiple standards and formats."""
    
    def __init__(self, standard: ValidationStandard = ValidationStandard.NTIA):
        """Initialize SBOM validator.
        
        Args:
            standard: Validation standard to use
        """
        self.standard = standard
        
    def validate_cyclonedx(self, sbom: str) -> ValidationResult:
        """Validate CycloneDX SBOM.
        
        Args:
            sbom: CycloneDX SBOM in XML format
            
        Returns:
            ValidationResult: Validation results
        """
        errors = []
        warnings = []
        
        # TODO: Implement CycloneDX validation
        # 1. Check schema validity
        # 2. Validate required fields based on standard
        # 3. Check component completeness
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
        
    def validate_spdx(self, document: Document) -> ValidationResult:
        """Validate SPDX document.
        
        Args:
            document: SPDX document
            
        Returns:
            ValidationResult: Validation results
        """
        errors = []
        warnings = []
        
        # TODO: Implement SPDX validation
        # 1. Check document validity
        # 2. Validate required fields based on standard
        # 3. Check package completeness
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
        
    def validate(self, sbom: Union[str, Document]) -> ValidationResult:
        """Validate SBOM against the specified standard.
        
        Args:
            sbom: SBOM to validate (CycloneDX XML string or SPDX Document)
            
        Returns:
            ValidationResult: Validation results
        """
        if isinstance(sbom, str):
            return self.validate_cyclonedx(sbom)
        else:
            return self.validate_spdx(sbom)
            
    def _validate_ntia_requirements(self, component: Component) -> List[str]:
        """Validate component against NTIA minimum requirements.
        
        Args:
            component: Component to validate
            
        Returns:
            List[str]: List of validation errors
        """
        errors = []
        
        # NTIA minimum requirements
        if not component.name:
            errors.append(f"Missing supplier name for component {component.name}")
            
        if not component.version:
            errors.append(f"Missing version for component {component.name}")
            
        if not component.supplier:
            errors.append(f"Missing supplier for component {component.name}")
            
        if not component.licenses:
            errors.append(f"Missing license information for component {component.name}")
            
        return errors
        
    def _validate_cisa_requirements(self, component: Component) -> List[str]:
        """Validate component against CISA requirements.
        
        Args:
            component: Component to validate
            
        Returns:
            List[str]: List of validation errors
        """
        errors = self._validate_ntia_requirements(component)  # CISA includes NTIA requirements
        
        # Additional CISA requirements
        if not component.purl:
            errors.append(f"Missing purl for component {component.name}")
            
        # TODO: Add more CISA-specific validations
        
        return errors 