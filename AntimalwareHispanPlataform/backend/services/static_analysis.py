"""
Static analysis service.
Handles PE parsing, YARA scanning, string extraction, etc.
"""

import os
import re
import math
import json
from typing import Dict, Any, List
import pefile
import yara
import magic
from api.v1.samples import storage # Circular import potential? No, storage is in services/storage.py, samples is api.
# Wait, storage was defined in services/storage.py
from services.storage import storage
from core.config import settings

# Regex patterns for string extraction
PATTERNS = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b"
}

class StaticAnalyzer:
    
    def __init__(self):
        self.yara_rules = self._load_yara_rules()

    def _load_yara_rules(self):
        """Load, compile and return YARA rules."""
        rules_path = settings.yara_rules_path
        if not os.path.exists(rules_path):
            return None
            
        filepaths = {}
        for root, dirs, files in os.walk(rules_path):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    filepaths[file] = os.path.join(root, file)
        
        if not filepaths:
            return None
            
        try:
            return yara.compile(filepaths=filepaths)
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            return None

    def analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Deep analysis of PE files."""
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError:
            return {}

        metadata = {
            "machine": pe.FILE_HEADER.Machine,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "sections": [],
            "imports": [],
            "exports": []
        }
        
        # Sections
        for section in pe.sections:
            metadata["sections"].append({
                "name": section.Name.decode().rstrip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy()
            })
            
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode()
                for imp in entry.imports:
                    func = imp.name.decode() if imp.name else f"ord({imp.ordinal})"
                    metadata["imports"].append({"dll": dll, "func": func})
                    
        return metadata

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_strings(self, data: bytes, min_len=4) -> Dict[str, List[str]]:
        """Extract ASCII strings and categorize them."""
        result = {
            "all": [],
            "ipv4": [],
            "email": [],
            "url": [],
            "domain": []
        }
        
        # Simple printable ASCII extraction
        # chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
        # regexp = f"[{chars}]{{{min_len},}}"
        # strings = re.findall(regexp.encode(), data)
        
        # Better: use regex for everything on the decoded latin-1 or similar
        try:
            text = data.decode('latin-1') 
        except:
            text = data.decode('ascii', errors='ignore')
            
        # General strings (naive)
        # For production use 'strings' linux util wrapper or robust binary parser
        # Here we just look for patterns
        
        for key, pattern in PATTERNS.items():
            found = re.findall(pattern, text)
            result[key] = list(set(found)) # Deduplicate
            
        return result

    def scan_yara(self, file_path: str) -> List[Dict[str, Any]]:
        """Run YARA scan."""
        if not self.yara_rules:
            return []
            
        try:
            matches = self.yara_rules.match(file_path)
            results = []
            for match in matches:
                results.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta
                })
            return results
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []

    async def run(self, file_path: str) -> Dict[str, Any]:
        """Run full static analysis pipeline."""
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # Basic Info
        file_type = magic.from_file(file_path)
        file_size = len(data)
        entropy = self.calculate_entropy(data)
        
        results = {
            "file_type": file_type,
            "file_size": file_size,
            "entropy": entropy,
            "pe_metadata": {},
            "strings": {},
            "yara_matches": []
        }
        
        # PE Analysis
        if "PE" in file_type or "executable" in file_type:
            results["pe_metadata"] = self.analyze_pe(file_path)
            
        # Strings
        results["strings"] = self.extract_strings(data)
        
        # YARA
        results["yara_matches"] = self.scan_yara(file_path)
        
        return results

# Global instance
static_analyzer = StaticAnalyzer()
