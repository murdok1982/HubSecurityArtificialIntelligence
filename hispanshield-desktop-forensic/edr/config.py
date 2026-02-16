import os
from dotenv import load_dotenv

load_dotenv()

class EDRConfig:
    BACKEND_URL = os.getenv("HISPANSHIELD_BACKEND_URL", "http://localhost:8000")
    API_KEY = os.getenv("HISPANSHIELD_API_KEY", "default-agent-key")
    DEVICE_ID = os.getenv("HISPANSHIELD_DEVICE_ID", "local-dev-id")
    
    # Scanning settings
    RULES_PATH = os.getenv("YARA_RULES_PATH", "./rules")
    WATCH_PATH = os.getenv("EDR_WATCH_PATH", "C:/") if os.name == 'nt' else os.getenv("EDR_WATCH_PATH", "/")
    
    # EDR Sensitivity
    PROCESS_LOG_INTERVAL = 5 # seconds
    
config = EDRConfig()
