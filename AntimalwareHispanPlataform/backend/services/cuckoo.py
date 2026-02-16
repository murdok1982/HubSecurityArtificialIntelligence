"""
Cuckoo CAPE Sandbox Integration.
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, Optional, List
import json

from core.config import settings

logger = logging.getLogger(__name__)

class CuckooClient:
    """Client for Cuckoo CAPE Sandbox API."""
    
    def __init__(self):
        self.base_url = settings.cuckoo_api_url
        self.token = settings.cuckoo_api_token
        self.headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        
    async def submit_file(self, file_path: str, options: Dict[str, Any] = None) -> Optional[int]:
        """
        Submit file for analysis.
        Returns task_id or None.
        """
        if not self.base_url:
            logger.warning("Cuckoo API URL not configured")
            return None
            
        url = f"{self.base_url}/tasks/create/file"
        data = aiohttp.FormData()
        
        try:
            # Open file in async context ideally, but aiohttp supports passing a file object
            # or reading bytes. Since we have paths, let's open it.
            # Using open() here is sync I/O blocking, but standard for aiohttp form upload
            # unless we use aiofiles to read into memory.
            with open(file_path, "rb") as f:
                data.add_field("file", f, filename=file_path.split("/")[-1])
                
                if options:
                    for k, v in options.items():
                        data.add_field(k, str(v))
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=data, headers=self.headers) as response:
                        if response.status == 200:
                            resp_json = await response.json()
                            return resp_json.get("task_id")
                        else:
                            logger.error(f"Cuckoo Submit Error {response.status}: {await response.text()}")
                            return None
        except Exception as e:
            logger.error(f"Cuckoo Submit Exception: {e}")
            return None

    async def get_task_status(self, task_id: int) -> str:
        """Get task status (pending, running, completed, reported)."""
        url = f"{self.base_url}/tasks/view/{task_id}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("task", {}).get("status", "unknown")
                    return "unknown"
            except Exception:
                return "unknown"

    async def get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """Get full analysis report."""
        url = f"{self.base_url}/tasks/report/{task_id}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
            except Exception:
                return None

# Global instance
cuckoo_client = CuckooClient()
