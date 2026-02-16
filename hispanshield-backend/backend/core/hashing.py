"""
Hashing utilities for file analysis.
Calculates MD5, SHA1, SHA256, SHA512, and SSDeep.
"""

import hashlib
from typing import BinaryIO, Dict
import ssdeep


def calculate_hashes(file_obj: BinaryIO) -> Dict[str, str]:
    """
    Calculate standard hashes for a file stream.
    Resets file pointer to beginning before and after.
    
    Returns:
        Dict with md5, sha1, sha256, sha512, ssdeep
    """
    algorithms = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    
    # Read entire content for ssdeep (it requires bytes or string, not stream usually)
    # Be careful with large files. For MVP huge files might exhaust RAM.
    # Production: Use chunking for standard hashes, 
    # and check ssdeep lib specifics for streaming or limit file size.
    
    file_obj.seek(0)
    content = file_obj.read()
    
    # Calculate standard hashes
    for algo in algorithms.values():
        algo.update(content)
        
    # Calculate SSDeep
    try:
        ssdeep_hash = ssdeep.hash(content)
    except Exception:
        ssdeep_hash = None
        
    # Reset pointer
    file_obj.seek(0)
    
    return {
        'md5': algorithms['md5'].hexdigest(),
        'sha1': algorithms['sha1'].hexdigest(),
        'sha256': algorithms['sha256'].hexdigest(),
        'sha512': algorithms['sha512'].hexdigest(),
        'ssdeep': ssdeep_hash
    }
