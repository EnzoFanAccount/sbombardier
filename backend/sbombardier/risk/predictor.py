"""
Risk prediction service integrating ML models with data collection and caching.
"""
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

import dgl
import numpy as np
import redis
import torch
from giskard import Model, ModelValidator
from trustyai.model import ModelAnalyzer

from ..ml.data.collectors import (LicenseCollector, MaintainerCollector,
                               VulnerabilityCollector)
from ..ml.models.risk_models import (HybridRiskPredictor, ModelType,
                                  RiskPrediction)

@dataclass
class ComponentRisk:
    """Risk assessment for a component."""
    name: str
    version: str
    risk_score: float
    risk_factors: List[str]
    suggested_remediation: Optional[str]
    license_conflicts: List[str]
    vulnerabilities: List[Dict]
    maintainer_score: float

class RiskPredictor:
    """Service for predicting component risks."""
    
    def __init__(self, 
                model_type: ModelType = ModelType.HYBRID,
                redis_url: Optional[str] = None,
                model_path: Optional[str] = None):
        """Initialize risk predictor.
        
        Args:
            model_type: Type of ML model to use
            redis_url: Redis URL for caching
            model_path: Path to pre-trained model
        """
        self.model_type = model_type
        self.model = HybridRiskPredictor()
        
        # Initialize data collectors
        self.vuln_collector = VulnerabilityCollector()
        self.license_collector = LicenseCollector()
        self.maintainer_collector = MaintainerCollector()
        
        # Initialize Redis cache
        self.redis = redis.from_url(redis_url) if redis_url else None
        
        # Initialize AI validation frameworks
        self.validator = ModelValidator()
        self.analyzer = ModelAnalyzer()
        
    def predict_component_risk(self, 
                            name: str,
                            version: str,
                            license_id: str,
                            repo_url: Optional[str] = None) -> ComponentRisk:
        """Predict risk for a component.
        
        Args:
            name: Component name
            version: Component version
            license_id: Component license ID
            repo_url: Optional repository URL
            
        Returns:
            ComponentRisk: Risk assessment
        """
        # Check cache first
        cache_key = f"risk:{name}:{version}"
        if self.redis:
            cached = self.redis.get(cache_key)
            if cached:
                return ComponentRisk(**json.loads(cached))
                
        # Collect data
        license_data = self._get_license_data(license_id)
        vuln_data = self._get_vulnerability_data(name, version)
        maintainer_data = self._get_maintainer_data(repo_url) if repo_url else None
        
        # Prepare inputs for ML models
        license_text = license_data.get("text", "")
        dependency_graph = self._build_dependency_graph(name, version)
        code_image = self._convert_code_to_image(name, version)
        
        # Get risk prediction
        prediction = self.model.predict(
            license_text=license_text,
            dependency_graph=dependency_graph,
            code_image=code_image
        )
        
        # Validate prediction
        self._validate_prediction(prediction)
        
        # Build remediation suggestions
        remediation = self._generate_remediation(
            prediction,
            license_data,
            vuln_data,
            maintainer_data
        )
        
        # Create risk assessment
        risk = ComponentRisk(
            name=name,
            version=version,
            risk_score=prediction.risk_score,
            risk_factors=prediction.risk_factors,
            suggested_remediation=remediation,
            license_conflicts=self._find_license_conflicts(license_id),
            vulnerabilities=vuln_data,
            maintainer_score=self._calculate_maintainer_score(maintainer_data)
        )
        
        # Cache result
        if self.redis:
            self.redis.setex(
                cache_key,
                3600,  # 1 hour TTL
                json.dumps(risk.__dict__)
            )
            
        return risk
        
    def _get_license_data(self, license_id: str) -> Dict:
        """Get license metadata.
        
        Args:
            license_id: License identifier
            
        Returns:
            Dict: License metadata
        """
        licenses = self.license_collector.collect_spdx_licenses()
        return next((l for l in licenses if l["id"] == license_id), {})
        
    def _get_vulnerability_data(self, name: str, version: str) -> List[Dict]:
        """Get vulnerability data for component.
        
        Args:
            name: Component name
            version: Component version
            
        Returns:
            List[Dict]: Vulnerability records
        """
        nvd_vulns = self.vuln_collector.collect_nvd_data()
        osv_vulns = self.vuln_collector.collect_osv_data()
        
        # Filter vulnerabilities affecting this component
        vulns = []
        for vuln in nvd_vulns + osv_vulns:
            if any(
                pkg.get("product", "").lower() == name.lower() and
                (pkg.get("version", "*") == "*" or pkg.get("version") == version)
                for pkg in vuln.get("affected_packages", [])
            ):
                vulns.append(vuln)
                
        return vulns
        
    def _get_maintainer_data(self, repo_url: str) -> Optional[Dict]:
        """Get maintainer activity data.
        
        Args:
            repo_url: Repository URL
            
        Returns:
            Optional[Dict]: Maintainer activity metrics
        """
        if not repo_url:
            return None
            
        # Extract owner/repo from URL
        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2:
            repo_name = f"{parts[-2]}/{parts[-1]}"
            return self.maintainer_collector.collect_repo_activity(repo_name)
            
        return None
        
    def _build_dependency_graph(self, name: str, version: str) -> dgl.DGLGraph:
        """Build dependency graph for GNN model.
        
        Args:
            name: Component name
            version: Component version
            
        Returns:
            dgl.DGLGraph: Dependency graph
        """
        # TODO: Implement proper graph construction
        # This is a placeholder that creates a simple graph
        num_nodes = 10
        src = torch.randint(0, num_nodes, (20,))
        dst = torch.randint(0, num_nodes, (20,))
        g = dgl.graph((src, dst))
        
        # Add random node features
        g.ndata["feat"] = torch.randn(num_nodes, 64)
        
        return g
        
    def _convert_code_to_image(self, name: str, version: str) -> torch.Tensor:
        """Convert code to grayscale image for CNN model.
        
        Args:
            name: Component name
            version: Component version
            
        Returns:
            torch.Tensor: Grayscale image tensor
        """
        # TODO: Implement proper code-to-image conversion
        # This is a placeholder that creates a random image
        return torch.randn(1, 64, 64)
        
    def _validate_prediction(self, prediction: RiskPrediction) -> None:
        """Validate model prediction using AI validation frameworks.
        
        Args:
            prediction: Model prediction to validate
        """
        # Wrap model for validation
        wrapped_model = Model(
            self.model,
            model_type="classification",
            feature_names=["license", "dependencies", "code"],
            classification_labels=["low_risk", "high_risk"]
        )
        
        # Run validation tests
        self.validator.test_model(
            wrapped_model,
            tests=[
                "performance",
                "fairness",
                "robustness"
            ]
        )
        
        # Run trustworthiness analysis
        self.analyzer.analyze(
            wrapped_model,
            metrics=[
                "bias",
                "explainability",
                "stability"
            ]
        )
        
    def _find_license_conflicts(self, license_id: str) -> List[str]:
        """Find conflicting licenses.
        
        Args:
            license_id: License to check
            
        Returns:
            List[str]: List of conflicting licenses
        """
        compatibility = self.license_collector.collect_license_compatibility()
        compatible = compatibility.get(license_id, [])
        all_licenses = set(compatibility.keys())
        
        return list(all_licenses - set(compatible))
        
    def _calculate_maintainer_score(self, maintainer_data: Optional[Dict]) -> float:
        """Calculate maintainer activity score.
        
        Args:
            maintainer_data: Maintainer activity metrics
            
        Returns:
            float: Maintainer score (0-1)
        """
        if not maintainer_data:
            return 0.5  # Neutral score if no data
            
        # Calculate score based on various metrics
        scores = []
        
        # Commit activity
        weekly_commits = maintainer_data.get("weekly_commits", [])
        if weekly_commits:
            commit_score = min(1.0, sum(weekly_commits) / (52 * 10))  # Expect 10 commits/week
            scores.append(commit_score)
            
        # Issue responsiveness
        open_issues = maintainer_data.get("open_issues_count", 0)
        total_issues = len(maintainer_data.get("closed_issues", [])) + open_issues
        if total_issues > 0:
            issue_score = 1 - (open_issues / total_issues)
            scores.append(issue_score)
            
        # Release frequency
        releases = maintainer_data.get("releases", [])
        if releases:
            latest = datetime.fromisoformat(releases[0]["published_at"].replace("Z", "+00:00"))
            age = (datetime.now() - latest).days
            release_score = 1.0 if age < 90 else max(0.0, 1 - (age - 90) / 275)
            scores.append(release_score)
            
        return sum(scores) / len(scores) if scores else 0.5
        
    def _generate_remediation(self,
                           prediction: RiskPrediction,
                           license_data: Dict,
                           vuln_data: List[Dict],
                           maintainer_data: Optional[Dict]) -> str:
        """Generate remediation suggestions.
        
        Args:
            prediction: Risk prediction
            license_data: License metadata
            vuln_data: Vulnerability data
            maintainer_data: Maintainer activity data
            
        Returns:
            str: Remediation suggestions
        """
        suggestions = []
        
        # License remediation
        if prediction.risk_score > 0.7:  # High license risk
            if license_data.get("id") == "AGPL-3.0":
                suggestions.append(
                    "Consider using MIT or Apache-2.0 licensed alternatives "
                    "to avoid strong copyleft requirements"
                )
                
        # Vulnerability remediation
        if vuln_data:
            suggestions.append(
                f"Found {len(vuln_data)} vulnerabilities. "
                "Update to the latest version or consider alternatives"
            )
            
        # Maintainer activity remediation
        maintainer_score = self._calculate_maintainer_score(maintainer_data)
        if maintainer_score < 0.3:
            suggestions.append(
                "Package shows low maintenance activity. "
                "Consider using a more actively maintained alternative"
            )
            
        return " ".join(suggestions) if suggestions else None 

    def predict_sbom_risk(self, components: List[Component]) -> float:
        """Calculate aggregate risk score for an SBOM."""
        total_risk = 0.0
        for component in components:
            risk = self.predict_component_risk(
                component.name,
                component.version,
                component.license_id,
                component.vulnerabilities
            )
            total_risk += risk.risk_score
            
        # Normalize score with nonlinear weighting
        return min(1.0, math.log(total_risk + 1) / 5.0) 