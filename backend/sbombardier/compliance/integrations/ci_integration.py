from typing import Dict, List, Optional, Union
import json
from pathlib import Path
import os
import aiofiles
from fastapi import HTTPException
from ..policies.policy_engine import PolicyEngine
from ..audit.audit_trail import AuditTrail
from datetime import datetime

class CIIntegration:
    def __init__(self):
        """Initialize CI integration with policy engine and audit trail."""
        self.policy_engine = PolicyEngine()
        self.audit_trail = AuditTrail()

    async def validate_pipeline(self, 
                       project_data: Dict,
                       sbom_data: Dict,
                       ci_platform: str = "github") -> Dict:
        """Validate project against compliance policies in CI pipeline."""
        try:
            # Validate SBOM against compliance frameworks
            frameworks = ["gdpr", "ccpa", "dora"]  # Add more as needed
            compliance_results = self.policy_engine.validate_sbom_compliance(sbom_data, frameworks)

            # Check license compliance
            licenses = [dep.get("license", "") for dep in sbom_data.get("dependencies", [])]
            license_check = self.policy_engine.check_license_compliance(
                licenses=licenses,
                project_license=project_data.get("license", "")
            )

            # Validate dependencies
            dependency_check = self.policy_engine.validate_dependency_policies(
                sbom_data.get("dependencies", [])
            )

            # Prepare validation result
            validation_result = {
                "compliant": all([
                    all(compliance_results.values()),
                    license_check.get("result", [{}])[0].get("allow", False),
                    dependency_check.get("result", [{}])[0].get("allow", False)
                ]),
                "framework_results": compliance_results,
                "license_check": license_check,
                "dependency_check": dependency_check
            }

            # Log validation event
            await self.audit_trail.log_event(
                event_type="ci_validation",
                event_data={
                    "project": project_data.get("name"),
                    "ci_platform": ci_platform,
                    "validation_result": validation_result
                },
                evidence_files=[self._generate_evidence_file(validation_result)]
            )

            return validation_result

        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Pipeline validation failed: {str(e)}"
            )

    async def generate_ci_config(self, 
                         project_data: Dict,
                         ci_platform: str = "github") -> Dict:
        """Generate CI configuration for compliance checks."""
        if ci_platform == "github":
            return await self._generate_github_workflow(project_data)
        elif ci_platform == "gitlab":
            return await self._generate_gitlab_ci(project_data)
        else:
            raise ValueError(f"Unsupported CI platform: {ci_platform}")

    async def _generate_github_workflow(self, project_data: Dict) -> Dict:
        """Generate GitHub Actions workflow for compliance checks."""
        workflow = {
            "name": "SBOMbardier Compliance Check",
            "on": ["push", "pull_request"],
            "jobs": {
                "compliance-check": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Checkout code",
                            "uses": "actions/checkout@v3"
                        },
                        {
                            "name": "Setup SBOMbardier",
                            "uses": "sbombardier/setup-action@v1",
                            "with": {
                                "project-id": project_data.get("id")
                            }
                        },
                        {
                            "name": "Generate SBOM",
                            "run": "sbombardier generate-sbom"
                        },
                        {
                            "name": "Run Compliance Check",
                            "run": "sbombardier validate-compliance"
                        }
                    ]
                }
            }
        }

        # Save workflow file
        workflows_dir = Path(".github/workflows")
        workflows_dir.mkdir(parents=True, exist_ok=True)
        
        workflow_path = workflows_dir / "sbombardier-compliance.yml"
        async with aiofiles.open(workflow_path, 'w') as f:
            await f.write(json.dumps(workflow, indent=2))

        return {"workflow_path": str(workflow_path), "content": workflow}

    async def _generate_gitlab_ci(self, project_data: Dict) -> Dict:
        """Generate GitLab CI configuration for compliance checks."""
        config = {
            "stages": ["compliance"],
            "compliance-check": {
                "stage": "compliance",
                "image": "sbombardier/ci-runner:latest",
                "script": [
                    "sbombardier generate-sbom",
                    "sbombardier validate-compliance"
                ],
                "artifacts": {
                    "reports": {
                        "sbom": "sbom.json",
                        "compliance": "compliance-report.json"
                    }
                }
            }
        }

        # Save GitLab CI config
        config_path = Path(".gitlab-ci.yml")
        async with aiofiles.open(config_path, 'w') as f:
            await f.write(json.dumps(config, indent=2))

        return {"config_path": str(config_path), "content": config}

    def _generate_evidence_file(self, validation_result: Dict) -> str:
        """Generate evidence file for validation result."""
        evidence_dir = Path("evidence")
        evidence_dir.mkdir(exist_ok=True)
        
        evidence_path = evidence_dir / f"validation_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(evidence_path, 'w') as f:
            json.dump(validation_result, f, indent=2)
            
        return str(evidence_path) 