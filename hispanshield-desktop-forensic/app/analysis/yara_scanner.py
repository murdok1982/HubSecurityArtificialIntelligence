import os
import yara
from app.config import YARA_RULES_PATH

class YaraScanner:
    def __init__(self):
        self.rules = None
        self.compile_rules()

    def compile_rules(self):
        filepaths = {}
        if not os.path.exists(YARA_RULES_PATH):
            return

        for root, dirs, files in os.walk(YARA_RULES_PATH):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    path = os.path.join(root, file)
                    # Use relative path or filename as key
                    filepaths[file] = path
        
        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except yara.Error as e:
                print(f"Error compiling YARA rules: {e}")
                self.rules = None

    def scan_file(self, file_path):
        if not self.rules:
            # Try to re-compile if empty (lazy loading or reliability)
            self.compile_rules()
            if not self.rules:
                return {"matches": [], "error": "No YARA rules compiled"}

        try:
            matches = self.rules.match(file_path)
            result = []
            for match in matches:
                result.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta
                })
            return {"matches": result}
        except Exception as e:
            return {"matches": [], "error": str(e)}

# Global instance
scanner = YaraScanner()

def run_yara_scan(case):
    return scanner.scan_file(case.file_path)
