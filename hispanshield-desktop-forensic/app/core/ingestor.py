import os
import shutil
import hashlib
import time
import mimetypes
import uuid
from datetime import datetime
try:
    import magic
except ImportError:
    magic = None

from app.config import CASES_DIR
from app.core.models import Case
from app.storage import db

def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
            
    return md5.hexdigest(), sha256.hexdigest()

def detect_file_type(file_path):
    if magic:
        try:
            return magic.from_file(file_path, mime=True)
        except Exception:
            pass
    
    mime, _ = mimetypes.guess_type(file_path)
    return mime or "application/octet-stream"

def ingest_file(original_path):
    if not os.path.exists(original_path):
        raise FileNotFoundError(f"File not found: {original_path}")
        
    # Basic info
    md5_hash, sha256_hash = calculate_hashes(original_path)
    file_size = os.path.getsize(original_path)
    
    # Create Case Directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_folder_name = f"{timestamp}_{sha256_hash[:8]}"
    case_dir = os.path.join(CASES_DIR, case_folder_name)
    os.makedirs(case_dir, exist_ok=True)
    
    # Copy file
    filename = os.path.basename(original_path)
    dest_path = os.path.join(case_dir, filename)
    shutil.copy2(original_path, dest_path)
    
    # Detect type
    file_type = detect_file_type(dest_path)
    
    # Create Case ID
    case_id = str(uuid.uuid4())
    
    # DB Entry
    case_data = {
        "id": case_id,
        "original_filename": filename,
        "file_path": dest_path,
        "file_size": file_size,
        "md5": md5_hash,
        "sha256": sha256_hash,
        "file_type": file_type
    }
    
    db.create_case(case_data)
    
    return Case(
        id=case_id,
        original_filename=filename,
        file_path=dest_path,
        file_size=file_size,
        md5=md5_hash,
        sha256=sha256_hash,
        file_type=file_type
    )
