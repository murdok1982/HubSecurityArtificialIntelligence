from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json

@dataclass
class Case:
    id: str
    original_filename: str
    file_path: str
    file_size: int
    md5: str
    sha256: str
    file_type: str
    status: str = "pending"
    risk_score: int = 0
    analysis_results: Dict = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "id": self.id,
            "original_filename": self.original_filename,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "status": self.status,
            "risk_score": self.risk_score,
            "analysis_results": self.analysis_results
        }
    
    @classmethod
    def from_db_row(cls, row):
        # Assumes row is a dict from db.get_case
        return cls(
            id=row['id'],
            original_filename=row['original_filename'],
            file_path=row['file_path'],
            file_size=row['file_size'],
            md5=row['md5'],
            sha256=row['sha256'],
            file_type=row['file_type'],
            status=row['status'],
            risk_score=row['risk_score'],
            analysis_results=json.loads(row['analysis_summary']) if row['analysis_summary'] else {}
        )

@dataclass
class IOC:
    type: str  # hash, ip, domain, url, registry, filepath
    value: str
    description: str = ""
    severity: str = "medium" # low, medium, high, critical

