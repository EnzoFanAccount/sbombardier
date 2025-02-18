"""
Data collectors for vulnerability, license, and maintainer activity data.
"""
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union

import nvdlib
import osv
import pandas as pd
import requests
from github import Github
from spdx.config import _licenses

class VulnerabilityCollector:
    """Collector for vulnerability data from NVD and OSV."""
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        """Initialize vulnerability collector.
        
        Args:
            nvd_api_key: NVD API key for higher rate limits
        """
        self.nvd_api_key = nvd_api_key or os.getenv("NVD_API_KEY")
        
    def collect_nvd_data(self, start_date: Optional[datetime] = None) -> List[Dict]:
        """Collect vulnerability data from NVD.
        
        Args:
            start_date: Start date for vulnerability collection
            
        Returns:
            List[Dict]: List of vulnerability records
        """
        if not start_date:
            start_date = datetime.now() - timedelta(days=365)  # Last year
            
        vulns = nvdlib.searchCVE(
            keywordSearch=None,
            pubStartDate=start_date,
            key=self.nvd_api_key
        )
        
        records = []
        for vuln in vulns:
            record = {
                "id": vuln.id,
                "description": vuln.descriptions[0].value if vuln.descriptions else "",
                "severity": vuln.metrics.cvssMetricV31[0].cvssData.baseScore if vuln.metrics.cvssMetricV31 else None,
                "cwe": vuln.weaknesses[0].description[0].value if vuln.weaknesses else None,
                "published_date": vuln.published,
                "references": [ref.url for ref in vuln.references] if vuln.references else [],
                "affected_packages": []
            }
            
            # Extract affected packages
            if hasattr(vuln, "configurations"):
                for config in vuln.configurations:
                    for node in config.nodes:
                        for cpe in node.cpeMatch:
                            if cpe.criteria:
                                parts = cpe.criteria.split(":")
                                if len(parts) > 4:
                                    record["affected_packages"].append({
                                        "vendor": parts[3],
                                        "product": parts[4],
                                        "version": parts[5] if len(parts) > 5 else "*"
                                    })
                                    
            records.append(record)
            
        return records
        
    def collect_osv_data(self) -> List[Dict]:
        """Collect vulnerability data with code snippets."""
        results = []
        
        # Get vulnerabilities from OSV API
        api = osv.OSV()
        query = osv.Query(ecosystem="PyPI", page_token=None)
        
        while True:
            response = api.query(query)
            for vuln in response.vulns:
                # Extract code snippets from affected versions
                snippets = self._extract_commit_snippets(vuln.affected[0].versions)
                results.append({
                    "description": vuln.details,
                    "severity": vuln.severity_score.cvss_v3.base_score,
                    "code_snippets": snippets,
                    "references": vuln.references
                })
                
            if not response.next_page_token:
                break
            query.page_token = response.next_page_token
            
        return results
    
    def _extract_commit_snippets(self, versions: List[str]) -> List[str]:
        """Extract code diffs from GitHub commits."""
        snippets = []
        for version in versions:
            try:
                commit_url = f"https://api.github.com/repos/{repo}/commits/{version}"
                response = requests.get(commit_url)
                diff = response.json()["files"][0]["patch"]
                snippets.append(self._clean_diff(diff))
            except Exception as e:
                continue
        return snippets

class LicenseCollector:
    """Collector for license metadata and compatibility information."""


    def __init__(self):
        self.osi_approved = {lid: lic.is_osi_approved for lid, lic in _licenses.items()}
        self.fsf_approved = {lid: lic.is_fsf_libre for lid, lic in _licenses.items()}
        self.compatibility_cache = None

    
    def collect_spdx_licenses(self) -> List[Dict]:
        """Collect license metadata from SPDX.
        
        Returns:
            List[Dict]: List of license records
        """
        records = []
        
        for license_id, license in _licenses.items():
            record = {
                "id": license_id,
                "name": license.full_name,
                "osi_approved": license.is_osi_approved,
                "fsf_libre": license.is_fsf_libre,
                "deprecated": license.is_deprecated,
                "text": license.text,
                "see_also": license.see_also
            }
            records.append(record)
            
        return records
        
    def collect_license_compatibility(self) -> Dict[str, List[str]]:
        """Collect license compatibility using SPDX data and known compatibility matrices."""
        if self.compatibility_cache:
            return self.compatibility_cache
            
        # Base compatibility on SPDX properties
        compatibility = {}
        for lid in _licenses:
            compatibility[lid] = []
            lic = _licenses[lid]
            
            # GPL-family compatibility rules
            if "gpl" in lid.lower():
                # Allow compatibility within same license family
                compatibility[lid].extend([
                    other_id for other_id in _licenses
                    if "gpl" in other_id.lower() and _licenses[other_id].version == lic.version
                ])
                
            # OSI-approved licenses are generally compatible
            if self.osi_approved.get(lid, False):
                compatibility[lid].extend([
                    other_id for other_id in _licenses
                    if self.osi_approved.get(other_id, False) and other_id not in compatibility[lid]
                ])

        # Add known exceptions from external sources
        compatibility.update({
            "MIT": ["Apache-2.0", "BSD-3-Clause", "ISC", "Python-2.0"],
            "Apache-2.0": ["MIT", "BSD-3-Clause", "LGPL-2.1", "LGPL-3.0"],
            "GPL-3.0": ["GPL-3.0", "LGPL-3.0", "AGPL-3.0"],
            "LGPL-3.0": ["GPL-3.0", "LGPL-3.0", "Apache-2.0", "MIT"]
        })
        
        self.compatibility_cache = compatibility
        return compatibility

    def get_license_compatibility(self, license_a: str, license_b: str) -> bool:
        """Check compatibility between two licenses using multiple factors."""
        compat_matrix = self.collect_license_compatibility()
        return (
            license_b in compat_matrix.get(license_a, []) or 
            license_a in compat_matrix.get(license_b, [])
        )

class MaintainerCollector:
    """Collector for repository maintainer activity data."""
    
    def __init__(self, github_token: Optional[str] = None):
        """Initialize maintainer collector.
        
        Args:
            github_token: GitHub API token
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.github = Github(self.github_token)
        
    def collect_repo_activity(self, repo_name: str) -> Dict:
        """Collect repository activity metrics.
        
        Args:
            repo_name: Repository name (owner/repo)
            
        Returns:
            Dict: Repository activity metrics
        """
        try:
            repo = self.github.get_repo(repo_name)
            
            # Get commit activity
            commit_activity = repo.get_stats_commit_activity()
            if commit_activity:
                weekly_commits = [week.total for week in commit_activity]
            else:
                weekly_commits = []
                
            # Get issue activity
            open_issues = repo.get_issues(state="open")
            closed_issues = repo.get_issues(state="closed")
            
            # Get release activity
            releases = repo.get_releases()
            
            metrics = {
                "name": repo_name,
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "open_issues_count": repo.open_issues_count,
                "last_commit": repo.pushed_at.isoformat() if repo.pushed_at else None,
                "weekly_commits": weekly_commits,
                "open_issues": [
                    {
                        "number": issue.number,
                        "title": issue.title,
                        "created_at": issue.created_at.isoformat(),
                        "labels": [label.name for label in issue.labels]
                    }
                    for issue in open_issues
                ],
                "closed_issues": [
                    {
                        "number": issue.number,
                        "title": issue.title,
                        "created_at": issue.created_at.isoformat(),
                        "closed_at": issue.closed_at.isoformat() if issue.closed_at else None,
                        "labels": [label.name for label in issue.labels]
                    }
                    for issue in closed_issues
                ],
                "releases": [
                    {
                        "tag": release.tag_name,
                        "name": release.title,
                        "published_at": release.published_at.isoformat() if release.published_at else None
                    }
                    for release in releases
                ]
            }
            
            return metrics
            
        except Exception as e:
            print(f"Error collecting data for {repo_name}: {str(e)}")
            return {} 