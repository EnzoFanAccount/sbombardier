"""
FastAPI service for SBOM generation and validation.
"""
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sbombardier.core.sbom_generator import SBOMFormat, SBOMGenerator
from sbombardier.risk.predictor import ComponentRisk, RiskPredictor
from sbombardier.validators.sbom_validator import ValidationResult, ValidationStandard, SBOMValidator

app = FastAPI(
    title="SBOMbardier",
    description="AI-powered SBOM generation and validation service",
    version="0.1.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class GenerateRequest(BaseModel):
    """Request model for SBOM generation."""
    format: SBOMFormat = SBOMFormat.CYCLONEDX
    project_path: str

class ValidationRequest(BaseModel):
    """Request model for SBOM validation."""
    standard: ValidationStandard = ValidationStandard.NTIA
    sbom_content: str

class RiskPredictionRequest(BaseModel):
    """Request model for risk prediction."""
    name: str
    version: str
    license_id: str
    repo_url: Optional[str] = None

# Initialize services
try:
    risk_predictor = RiskPredictor(use_ml=True)
except Exception as e:
    print(f"Warning: Could not initialize RiskPredictor with ML features: {e}")
    print("Falling back to non-ML risk prediction")
    risk_predictor = RiskPredictor(use_ml=False)

@app.post("/generate", response_model=Dict[str, Union[str, List[str]]])
async def generate_sbom(request: GenerateRequest):
    """Generate SBOM for a project.
    
    Args:
        request: Generation request containing format and project path
        
    Returns:
        Dict containing generated SBOM and any warnings
    """
    try:
        generator = SBOMGenerator(request.project_path, request.format)
        sbom = generator.generate()
        
        return {
            "sbom": str(sbom),
            "warnings": []  # TODO: Add generation warnings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/validate", response_model=ValidationResult)
async def validate_sbom(request: ValidationRequest):
    """Validate an SBOM against specified standard.
    
    Args:
        request: Validation request containing standard and SBOM content
        
    Returns:
        ValidationResult containing validation status and any errors/warnings
    """
    try:
        validator = SBOMValidator(request.standard)
        result = validator.validate(request.sbom_content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict-risk", response_model=ComponentRisk)
async def predict_risk(request: RiskPredictionRequest):
    """Predict risk for a component.
    
    Args:
        request: Risk prediction request
        
    Returns:
        ComponentRisk containing risk assessment
    """
    try:
        risk = risk_predictor.predict_component_risk(
            name=request.name,
            version=request.version,
            license_id=request.license_id,
            repo_url=request.repo_url
        )
        return risk
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload", response_model=Dict[str, str])
async def upload_project(file: UploadFile = File(...)):
    """Upload a project archive for SBOM generation.
    
    Args:
        file: Project archive file
        
    Returns:
        Dict containing the temporary path where the project was extracted
    """
    try:
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Save uploaded file
            file_path = temp_path / file.filename
            with open(file_path, "wb") as f:
                content = await file.read()
                f.write(content)
                
            # TODO: Extract archive if needed
            
            return {"project_path": str(temp_path)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 