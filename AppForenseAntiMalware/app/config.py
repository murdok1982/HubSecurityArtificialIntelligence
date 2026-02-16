import os
import sys

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CASES_DIR = os.path.join(BASE_DIR, "cases")
DB_PATH = os.path.join(BASE_DIR, "storage", "malware_cases.db")
ASSETS_DIR = os.path.join(BASE_DIR, "gui", "assets") # For icons/logos

# Analysis Configuration
ENABLE_SANDBOX = False  # Set to True when Sandbox is ready
SANDBOX_URL = "http://127.0.0.1:8090"  # Example Cuckoo/Sandbox URL
SANDBOX_API_KEY = "CHANGE_ME"

YARA_RULES_PATH = os.path.join(BASE_DIR, "analysis", "rules")

# External GPT Agents
AGENT_URL_REVERSING = "https://chatgpt.com/g/g-6743783cf67081919e17064f481f8005-reversing-and-exploitation-expert"
AGENT_URL_INTEL = "https://chatgpt.com/g/g-67643cde06748191b5dcadf706cbfd86-cyber-intelligence-analyst"
AGENT_URL_HOST_GLC = "https://chatgpt.com/g/g-gONwzvsMu-asesor-ciberseguridad-glc"
AGENT_URL_INDUSTRIAL = "https://chatgpt.com/g/g-68165162e8ec8191ada432d1c5221995-cyber-industrial-expert"

# Reporting
ORGANIZATION_NAME = "Malware Forensics Lab"
ANALYST_NAME = "Automated System"

# Ensure dirs exist
os.makedirs(CASES_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
