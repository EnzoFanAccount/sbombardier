from typing import Dict, List, Optional
import json
from datetime import datetime
from pathlib import Path
import jinja2
import aiofiles
from ..audit.audit_trail import AuditTrail

class ReportGenerator:
    def __init__(self, template_dir: str = "report_templates"):
        """Initialize the report generator with a template directory."""
        self.template_dir = Path(template_dir)
        self.template_loader = jinja2.FileSystemLoader(searchpath=str(self.template_dir))
        self.template_env = jinja2.Environment(loader=self.template_loader)
        self.audit_trail = AuditTrail()

    async def generate_compliance_report(self,
                                project_id: str,
                                framework: str,
                                start_date: Optional[datetime] = None,
                                end_date: Optional[datetime] = None) -> Dict:
        """Generate a compliance report for a specific framework."""
        # Get audit trail data
        audit_data = await self.audit_trail.get_audit_trail(
            event_type=f"{framework}_compliance",
            start_time=start_date,
            end_time=end_date
        )

        # Prepare report data
        report_data = {
            "project_id": project_id,
            "framework": framework,
            "generated_at": datetime.utcnow().isoformat(),
            "period": {
                "start": start_date.isoformat() if start_date else "N/A",
                "end": end_date.isoformat() if end_date else "N/A"
            },
            "audit_entries": audit_data,
            "summary": self._generate_summary(audit_data)
        }

        # Generate report using template
        template = self.template_env.get_template(f"{framework}_report.html")
        report_html = template.render(report_data)

        # Save report
        report_id = f"{project_id}_{framework}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        await self._save_report(report_id, report_html, report_data)

        return {
            "report_id": report_id,
            "framework": framework,
            "generated_at": report_data["generated_at"],
            "summary": report_data["summary"]
        }

    def _generate_summary(self, audit_data: List[Dict]) -> Dict:
        """Generate a summary of audit data."""
        total_events = len(audit_data)
        compliant_events = sum(1 for entry in audit_data 
                             if entry["event_data"].get("compliant", False))
        
        return {
            "total_events": total_events,
            "compliant_events": compliant_events,
            "compliance_rate": (compliant_events / total_events * 100) if total_events > 0 else 0,
            "last_check": audit_data[0]["timestamp"] if audit_data else None
        }

    async def _save_report(self, report_id: str, report_html: str, report_data: Dict):
        """Save the generated report."""
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        # Save HTML report
        html_path = reports_dir / f"{report_id}.html"
        async with aiofiles.open(html_path, 'w') as f:
            await f.write(report_html)

        # Save JSON data
        json_path = reports_dir / f"{report_id}.json"
        async with aiofiles.open(json_path, 'w') as f:
            await f.write(json.dumps(report_data, indent=2))

    async def get_report(self, report_id: str, format: str = "html") -> str:
        """Retrieve a generated report."""
        reports_dir = Path("reports")
        report_path = reports_dir / f"{report_id}.{format}"
        
        if not report_path.exists():
            raise FileNotFoundError(f"Report {report_id} not found in {format} format")

        async with aiofiles.open(report_path, 'r') as f:
            return await f.read()

    async def generate_gdpr_report(self, project_id: str, data_processing_info: Dict) -> Dict:
        """Generate a GDPR-specific compliance report."""
        report_data = {
            "project_id": project_id,
            "data_processing": data_processing_info,
            "generated_at": datetime.utcnow().isoformat(),
            "audit_trail": await self.audit_trail.get_audit_trail(event_type="gdpr_compliance")
        }
        
        template = self.template_env.get_template("gdpr_report.html")
        report_html = template.render(report_data)
        
        report_id = f"gdpr_{project_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        await self._save_report(report_id, report_html, report_data)
        
        return {"report_id": report_id, "framework": "GDPR"}

    async def generate_ccpa_report(self, project_id: str, privacy_info: Dict) -> Dict:
        """Generate a CCPA-specific compliance report."""
        report_data = {
            "project_id": project_id,
            "privacy_info": privacy_info,
            "generated_at": datetime.utcnow().isoformat(),
            "audit_trail": await self.audit_trail.get_audit_trail(event_type="ccpa_compliance")
        }
        
        template = self.template_env.get_template("ccpa_report.html")
        report_html = template.render(report_data)
        
        report_id = f"ccpa_{project_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        await self._save_report(report_id, report_html, report_data)
        
        return {"report_id": report_id, "framework": "CCPA"} 