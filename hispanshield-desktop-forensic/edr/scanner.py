import yara
import os
import hashlib
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class EDRScanner:
    """
    Threat detection engine using YARA and hash matching.
    """
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = None
        self.load_rules()

    def load_rules(self):
        """Compile YARA rules from the rules directory."""
        try:
            rule_files = {}
            if os.path.exists(self.rules_path):
                for f in os.listdir(self.rules_path):
                    if f.endswith('.yar') or f.endswith('.yara'):
                        rule_files[f] = os.path.join(self.rules_path, f)
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                logger.info(f"Loaded {len(rule_files)} YARA rule files.")
            else:
                logger.warning("No YARA rules found to load.")
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a file using YARA rules and calculate hash."""
        results = {
            "path": file_path,
            "hash": self._calculate_sha256(file_path),
            "detections": [],
            "status": "clean"
        }
        
        if not self.rules:
            return results

        try:
            matches = self.rules.match(file_path)
            if matches:
                results["status"] = "malicious"
                results["detections"] = [str(m) for m in matches]
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            results["status"] = "error"
            results["error"] = str(e)
            
        return results

    def _calculate_sha256(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return None
