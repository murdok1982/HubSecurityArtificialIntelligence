"""
Storage service for handling file uploads and downloads.
Supports local filesystem and S3 (minio/aws).
"""

import os
import shutil
from pathlib import Path
from typing import BinaryIO, Optional
import aiofiles

from core.config import settings


class StorageService:
    """Abstracts storage backend operations."""
    
    def __init__(self):
        self.backend = settings.storage_backend
        self.local_path = Path(settings.local_storage_path)
        
        # Ensure local directories exist
        if self.backend == "local":
            (self.local_path / "samples").mkdir(parents=True, exist_ok=True)
            (self.local_path / "artifacts").mkdir(parents=True, exist_ok=True)
            
        # TODO: Initialize S3 client if backend is s3
        self.s3_client = None

    async def save_sample(self, file_obj: BinaryIO, filename: str, tenant_id: str, sample_id: str) -> str:
        """
        Save a sample file to storage.
        
        Args:
            file_obj: File-like object (bytes)
            filename: Original filename
            tenant_id: Tenant UUID
            sample_id: Sample UUID
            
        Returns:
            str: Storage path or URI/Key
        """
        if self.backend == "local":
            # Structure: storage/samples/{tenant_id}/{sample_id}
            # We use distinct file per sample ID even if hash is same, 
            # to allow diverse metadata/filenames per tenant.
            # Deduplication logic happens at DB level/Analysis level, 
            # but physically storing copy simplifies multi-tenant isolation for MVP.
            # In v2 we can optimize storage with content-addressable storage (CAS).
            
            target_dir = self.local_path / "samples" / str(tenant_id)
            target_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = target_dir / str(sample_id)
            
            async with aiofiles.open(file_path, 'wb') as out_file:
                # If file_obj is spooled (FastAPI UploadFile), read in chunks
                while content := await file_obj.read(1024 * 1024):  # 1MB chunks
                    await out_file.write(content)
            
            return str(file_path)
            
        elif self.backend == "s3":
            # TODO: Implement S3 upload
            key = f"{tenant_id}/samples/{sample_id}"
            # await self.s3_client.upload_fileobj(...)
            return f"s3://{settings.s3_bucket}/{key}"
            
        raise ValueError(f"Unsupported storage backend: {self.backend}")

    async def get_sample_path(self, storage_path: str) -> str:
        """
        Get absolute local path for a sample. 
        If S3, downloads to temp file (not implemented in MVP).
        """
        if self.backend == "local":
            return str(Path(storage_path).absolute())
        
        raise NotImplementedError("S3 download not implemented yet")


# Global instance
storage = StorageService()
