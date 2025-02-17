"""
SBOM validation module supporting NTIA and CISA standards.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Union

from cyclonedx.model import Component
from spdx.document import Document
from cyclonedx.model import Bom
from cyclonedx.exceptions import ParseError
from spdx.parsers.parse import SPDXParsingError
from spdx.parsers.lexers import SPDXLexerError
from spdx.exceptions import SPDXValueError, SPDXException

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
        
        try:
            bom = Bom.parse(sbom)
            
            # 1. Schema validity (handled by parse exception)
            
            # 2. Validate required fields based on standard
            if self.standard == ValidationStandard.CISA:
                # Verify CISA-specific metadata
                if not bom.metadata.properties.get("sbom_type"):
                    errors.append("Missing CISA SBOM type classification")
                
                # Check schema version compliance
                if bom.version != "1.5" and bom.version < "1.5":
                    errors.append(f"Unsupported CycloneDX version {bom.version}. CISA requires 1.5+")
            
            # 3. Component completeness checks
            for component in bom.components:
                # Validate against CISA requirements
                component_errors = self._validate_cisa_requirements(component)
                errors.extend(component_errors)
                
                # CISA hash requirement validation
                if not component.hashes:
                    errors.append(f"Missing cryptographic hashes for component {component.name} (CISA Minimum Expected)")
                
                # Check for redaction compliance
                if component.name == "[REDACTED]":
                    if not (component.version and component.hashes and component.dependencies):
                        errors.append(f"Redacted component missing required fields (version, hashes, or dependencies)")

        except ParseError as e:
            errors.append(f"Invalid CycloneDX format: {str(e)}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
        
    def validate_spdx(self, document: Document) -> ValidationResult:
        """Validate SPDX document."""
        errors = []
        warnings = []
        
        try:
            # 1. Document validity - use SPDX's built-in validation
            from spdx.validation.document import validate_document
            validation_messages = validate_document(document)
            
            if validation_messages:
                errors.extend(str(msg) for msg in validation_messages)

            # 2. Validate required fields based on standard
            if self.standard == ValidationStandard.CISA:
                # CISA metadata checks
                if not document.creation_info.creators:
                    errors.append("Missing document creators (CISA Minimum Expected)")
                
                # SPDX version check using proper version comparison
                if not (document.version.major == 2 and document.version.minor >= 3):
                    errors.append(f"Unsupported SPDX version {document.version}. CISA requires 2.3+")

            # 3. Package completeness checks
            for package in document.packages:
                # CISA Minimum Expected
                if not package.spdx_id:
                    errors.append(f"Missing SPDX ID for package {package.name}")
                
                # Use SPDX's package validation
                from spdx.validation.package import validate_package
                package_errors = validate_package(package)
                if package_errors:
                    errors.extend(str(err) for err in package_errors)

        except (SPDXValueError, SPDXParsingError) as e:
            errors.append(f"SPDX validation failed: {str(e)}")
        except SPDXException as e:
            errors.append(f"SPDX processing error: {str(e)}")
        
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
        result = super().validate(sbom)

        if isinstance(sbom, str):
            if "<Design>" in sbom and "<Deployed>" in sbom:
                result.errors.append("CISA violation: Mixed SBOM types detected")
                
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
        """Validate component against CISA requirements."""
        errors = self._validate_ntia_requirements(component)  # Inherit NTIA requirements
        
        # CISA Minimum Expected Fields
        if not component.purl:
            errors.append(f"Missing purl for component {component.name}")
            
        if not component.hashes:
            errors.append(f"Missing cryptographic hashes for component {component.name}")
            
        # CISA Recommended Practice
        if not component.copyright:
            errors.append(f"Missing copyright information for component {component.name}")
            
        if not component.dependencies:
            warnings.append(f"Missing explicit dependency relationships for component {component.name}")
            
        # CISA Aspirational Goals
        if hasattr(component, 'properties'):
            eol_date = next((p.value for p in component.properties if p.name == "eol"), None)
            if not eol_date:
                warnings.append(f"Missing end-of-life date for component {component.name}")
                
            tech_compat = next((p.value for p in component.properties if p.name == "tech_compatibility"), None)
            if not tech_compat:
                warnings.append(f"Missing technology compatibility info for component {component.name}")

        # CISA Authentication Requirements
        if not component.signature:
            errors.append(f"Missing digital signature for component {component.name}")

        return errors 