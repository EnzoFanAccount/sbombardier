from typing import Dict, List, Optional
import json
import subprocess
from pathlib import Path
from fastapi import HTTPException

class PolicyEngine:
    def __init__(self, policy_dir: str = "policies/rego"):
        """Initialize the policy engine with a directory of Rego policies."""
        self.policy_dir = Path(policy_dir)
        self._validate_opa_installation()

    def _validate_opa_installation(self):
        """Check if OPA is installed and accessible."""
        try:
            subprocess.run(["opa", "version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("OPA is not installed or not accessible. Please install OPA first.")

    def evaluate_policy(self, policy_name: str, input_data: Dict) -> Dict:
        """Evaluate a specific policy against input data."""
        policy_path = self.policy_dir / f"{policy_name}.rego"
        if not policy_path.exists():
            raise HTTPException(status_code=404, detail=f"Policy {policy_name} not found")

        try:
            # Convert input data to JSON
            input_json = json.dumps(input_data)
            
            # Run OPA evaluation
            result = subprocess.run(
                ["opa", "eval", "--data", str(policy_path), "--input", input_json, "data.sbombardier.allow"],
                capture_output=True,
                text=True,
                check=True
            )
            
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Policy evaluation failed: {e.stderr}")

    def validate_sbom_compliance(self, sbom_data: Dict, frameworks: List[str]) -> Dict[str, bool]:
        """Validate SBOM against multiple compliance frameworks."""
        results = {}
        for framework in frameworks:
            policy_result = self.evaluate_policy(f"{framework}_compliance", sbom_data)
            results[framework] = policy_result.get("result", [{}])[0].get("allow", False)
        return results

    def check_license_compliance(self, licenses: List[str], project_license: str) -> Dict:
        """Check license compatibility with project license."""
        input_data = {
            "licenses": licenses,
            "project_license": project_license
        }
        return self.evaluate_policy("license_compatibility", input_data)

    def validate_dependency_policies(self, dependencies: List[Dict]) -> Dict:
        """Validate dependencies against security and compliance policies."""
        input_data = {"dependencies": dependencies}
        return self.evaluate_policy("dependency_policies", input_data) 