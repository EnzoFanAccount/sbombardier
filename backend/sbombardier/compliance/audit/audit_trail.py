from datetime import datetime
from typing import Dict, List, Optional
import json
from pathlib import Path
import hashlib
from fastapi import HTTPException
import aiofiles
import os

class AuditTrail:
    def __init__(self, audit_dir: str = "audit_logs"):
        """Initialize the audit trail with a directory for storing logs."""
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)

    async def log_event(self, 
                 event_type: str,
                 event_data: Dict,
                 evidence_files: Optional[List[str]] = None) -> str:
        """Log an event with associated data and evidence files."""
        timestamp = datetime.utcnow().isoformat()
        event_id = self._generate_event_id(event_type, timestamp)
        
        audit_entry = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "event_data": event_data,
            "evidence_hashes": []
        }

        # Process evidence files if provided
        if evidence_files:
            evidence_hashes = await self._process_evidence_files(event_id, evidence_files)
            audit_entry["evidence_hashes"] = evidence_hashes

        # Write audit log
        await self._write_audit_log(event_id, audit_entry)
        return event_id

    def _generate_event_id(self, event_type: str, timestamp: str) -> str:
        """Generate a unique event ID."""
        data = f"{event_type}-{timestamp}".encode()
        return hashlib.sha256(data).hexdigest()[:16]

    async def _process_evidence_files(self, event_id: str, evidence_files: List[str]) -> List[Dict]:
        """Process and store evidence files with their hashes."""
        evidence_hashes = []
        evidence_dir = self.audit_dir / "evidence" / event_id
        evidence_dir.mkdir(parents=True, exist_ok=True)

        for file_path in evidence_files:
            if not os.path.exists(file_path):
                continue

            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
                file_hash = hashlib.sha256(content).hexdigest()

            # Copy evidence file to audit directory
            file_name = Path(file_path).name
            evidence_path = evidence_dir / file_name
            async with aiofiles.open(evidence_path, 'wb') as f:
                await f.write(content)

            evidence_hashes.append({
                "file_name": file_name,
                "hash": file_hash,
                "stored_path": str(evidence_path)
            })

        return evidence_hashes

    async def _write_audit_log(self, event_id: str, audit_entry: Dict):
        """Write audit entry to log file."""
        log_file = self.audit_dir / f"{event_id}.json"
        async with aiofiles.open(log_file, 'w') as f:
            await f.write(json.dumps(audit_entry, indent=2))

    async def get_audit_trail(self, 
                      event_type: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None) -> List[Dict]:
        """Retrieve audit trail entries with optional filtering."""
        audit_entries = []
        
        for log_file in self.audit_dir.glob("*.json"):
            if not log_file.is_file() or not log_file.suffix == '.json':
                continue

            async with aiofiles.open(log_file, 'r') as f:
                content = await f.read()
                entry = json.loads(content)

                # Apply filters
                if event_type and entry["event_type"] != event_type:
                    continue
                
                entry_time = datetime.fromisoformat(entry["timestamp"])
                if start_time and entry_time < start_time:
                    continue
                if end_time and entry_time > end_time:
                    continue

                audit_entries.append(entry)

        return sorted(audit_entries, key=lambda x: x["timestamp"], reverse=True)

    async def get_evidence(self, event_id: str) -> List[Dict]:
        """Retrieve evidence files for a specific event."""
        log_file = self.audit_dir / f"{event_id}.json"
        if not log_file.exists():
            raise HTTPException(status_code=404, detail=f"Audit event {event_id} not found")

        async with aiofiles.open(log_file, 'r') as f:
            content = await f.read()
            entry = json.loads(content)
            return entry.get("evidence_hashes", []) 