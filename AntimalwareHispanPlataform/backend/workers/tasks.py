"""
Celery tasks implementation.
"""

from asgiref.sync import async_to_sync
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from uuid import UUID
import json
from datetime import datetime

from typing import List
from .celery_app import celery_app
from core.config import settings
from services.static_analysis import static_analyzer
from services.storage import storage
from models.database import Analysis, AnalysisStatus, AnalysisType
import requests

# Helper for Sync DB access in Celery
# Since Celery is sync by default and our main app is async
# We create a separate sync engine for workers
sync_engine = create_engine(
    settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
)
SessionLocal = sessionmaker(bind=sync_engine)


@celery_app.task(name="workers.tasks.static_analysis_task")
def static_analysis_task(analysis_id: str, tenant_id: str):
    """
    Perform static analysis on a sample.
    """
    db = SessionLocal()
    try:
        # 1. Fetch Analysis record
        analysis = db.query(Analysis).filter(Analysis.id == UUID(analysis_id)).first()
        if not analysis:
            return "Analysis not found"
            
        analysis.status = AnalysisStatus.RUNNING
        analysis.started_at = datetime.utcnow()
        db.commit()
        
        # 2. Get Sample path
        # Need to fetch sample first
        from models.database import Sample
        sample = db.query(Sample).filter(Sample.id == analysis.sample_id).first()
        
        # Resolve path
        # Ideally storage service has a sync method or we run async_to_sync
        # For now, let's assume local storage and assume path valid
        # In real world: storage.get_sync_path(sample.storage_path)
        
        # Hack for MVP local storage:
        file_path = sample.storage_path 
        
        # 3. Run Analysis
        # Run the async run method synchronously
        results = async_to_sync(static_analyzer.run)(file_path)
        
        # 4. Save results
        analysis.static_results = results
        # Determine risk score (naive)
        score = 0
        if results['yara_matches']:
            score += 50
        if results['entropy'] > 7.0:
            score += 20
        analysis.risk_score = min(score, 100)
        
        # Trigger VirusTotal / Triage Phase
        vt_lookup_task.delay(analysis_id, tenant_id, results['yara_matches'])
        
        return f"Static Analysis {analysis_id} completed"
        
    except Exception as e:
        if 'analysis' in locals() and analysis:
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(e)
            db.commit()
        raise e
    finally:
        db.close()


@celery_app.task(name="workers.tasks.vt_lookup_task")
def vt_lookup_task(analysis_id: str, tenant_id: str, yara_matches: List[dict]):
    """
    Perform VirusTotal lookup and decide triage.
    """
    db = SessionLocal()
    try:
        # 1. Fetch Analysis & Sample
        from models.database import Sample
        analysis = db.query(Analysis).filter(Analysis.id == UUID(analysis_id)).first()
        sample = db.query(Sample).filter(Sample.id == analysis.sample_id).first()
        
        # 2. Call VirusTotal (Sync wrapper needed for Celery)
        # Note: In production use async celery tasks or run loop
        import requests
        
        vt_data = None
        if settings.virustotal_api_key:
            headers = {"x-apikey": settings.virustotal_api_key}
            resp = requests.get(f"{settings.virustotal_api_url}/files/{sample.sha256}", headers=headers)
            if resp.status_code == 200:
                vt_data = resp.json().get("data", {}).get("attributes", {})
        
        # 3. Process VT Results
        vt_score = 0
        if vt_data:
             stats = vt_data.get("last_analysis_stats", {})
             malicious = stats.get("malicious", 0)
             total = sum(stats.values())
             analysis.vt_detections = malicious
             
             # Simple heuristics
             if malicious > 0:
                 vt_score = (malicious / total) * 100 if total > 0 else 0
        
        # 4. Triage Decision
        # Combine Static + VT scores
        static_score = analysis.risk_score or 0
        final_score = max(static_score, vt_score)
        
        analysis.risk_score = int(final_score)
        
        # Decision Logic
        # If very malicious (VT > 40 detections) -> Skip dynamic to save resources?
        # Or always run dynamic if analysis_type=FULL?
        # For MVP: Always run dynamic if type is FULL or DYNAMIC
        
        should_run_dynamic = (
            analysis.analysis_type in [AnalysisType.DYNAMIC, AnalysisType.FULL] 
            # and final_score < 90  # Example optimization
        )
        
        if should_run_dynamic:
            # Trigger Dynamic Analysis
            # Recursive task call (import here to avoid circular dependency at top level if needed, 
            # though tasks.py defines both so it's fine to call by name string or object)
            dynamic_analysis_task.delay(analysis_id, tenant_id)
        else:
            # Finalize immediately
            analysis.status = AnalysisStatus.COMPLETED
            analysis.completed_at = datetime.utcnow()
            
        db.commit()
        return f"Triage {analysis_id} completed. VT Detections: {analysis.vt_detections}"
        
    except Exception as e:
         print(f"Triage error: {e}")
         # Don't fail analysis, just log and continue/finish
         if 'analysis' in locals() and analysis:
             db.commit()
    finally:
        db.close()

@celery_app.task(name="workers.tasks.dynamic_analysis_task")
def dynamic_analysis_task(analysis_id: str, tenant_id: str):
    """
    Perform Dynamic Analysis using Cuckoo CAPE.
    Note: Using synchronous requests here for Celery compatibility.
    """
    db = SessionLocal()
    try:
        # 1. Setup
        from models.database import Sample
        import time
        import requests
        
        analysis = db.query(Analysis).filter(Analysis.id == UUID(analysis_id)).first()
        if not analysis:
            return
            
        sample = db.query(Sample).filter(Sample.id == analysis.sample_id).first()
        file_path = sample.storage_path
        
        # 2. Submit to Cuckoo
        task_id = None
        if settings.cuckoo_api_url:
            files = {'file': open(file_path, 'rb')}
            try:
                # Add options like timeout, machine, etc.
                data = {'timeout': settings.cuckoo_timeout}
                resp = requests.post(f"{settings.cuckoo_api_url}/tasks/create/file", files=files, data=data)
                if resp.status_code == 200:
                    task_id = resp.json().get("task_id")
            except Exception as e:
                print(f"Cuckoo Submit Error: {e}")
                
        if not task_id:
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = "Failed to submit to sandbox"
            db.commit()
            return
            
        analysis.status = AnalysisStatus.RUNNING
        analysis.sandbox = "cuckoo_cape"
        db.commit()
        
        # 3. Poll for completion
        # Max wait time from settings + overhead
        max_wait = settings.cuckoo_timeout + 300 
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                status_resp = requests.get(f"{settings.cuckoo_api_url}/tasks/view/{task_id}")
                if status_resp.status_code == 200:
                    status_data = status_resp.json().get("task", {}).get("status")
                    if status_data == "reported":
                        break
                    elif status_data == "failed":
                        raise Exception("Sandbox analysis failed internally")
            except Exception as e:
                print(f"Polling error: {e}")
                
            time.sleep(15) # Poll every 15s
            
        # 4. Get Results
        report_resp = requests.get(f"{settings.cuckoo_api_url}/tasks/report/{task_id}")
        if report_resp.status_code == 200:
            report_data = report_resp.json()
            
            # Normalize report (extract key info)
            dynamic_results = {
                "task_id": task_id,
                "score": report_data.get("info", {}).get("score", 0),
                "behavior": {
                    "processes": len(report_data.get("behavior", {}).get("processes", [])),
                    "files": len(report_data.get("behavior", {}).get("summary", {}).get("files", [])),
                    "network": len(report_data.get("network", {}).get("http", []))
                }
                # Add more fields as needed (signatures, MITRE, etc.)
            }
            
            # Update Analysis
            analysis.dynamic_results = dynamic_results
            
            # Calculate final risk score
            # Naive: max of static, vt, dynamic
            current_risk = analysis.risk_score or 0
            dynamic_score = dynamic_results["score"] * 10 # Cuckoo usually 0-10, scale to 100
            analysis.risk_score = max(current_risk, int(dynamic_score))
            
            analysis.status = AnalysisStatus.COMPLETED
            analysis.completed_at = datetime.utcnow()
            db.commit()
            return f"Dynamic Analysis {analysis_id} completed (Task {task_id})"
            
        else:
             raise Exception("Failed to retrieve sandbox report")

    except Exception as e:
        if 'analysis' in locals() and analysis:
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = f"Dynamic engine error: {str(e)}"
            db.commit()
        raise e
    finally:
        db.close()
@celery_app.task(name="workers.tasks.sync_cti_feeds_task")
def sync_cti_feeds_task():
    """
    Scheduled task to refresh Threat Intelligence feeds.
    Run daily/hourly via Celery Beat.
    """
    from services.intel_service import IntelService
    
    db = SessionLocal()
    try:
        service = IntelService(db)
        # We run these synchronously in the worker context
        import asyncio
        loop = asyncio.get_event_loop()
        
        urlhaus_new = loop.run_until_complete(service.fetch_urlhaus())
        phishtank_new = loop.run_until_complete(service.fetch_phishtank())
        
        return f"CTI Sync completed. New IoCs: URLhaus={urlhaus_new}, PhishTank={phishtank_new}"
    except Exception as e:
        print(f"CTI Sync error: {e}")
        return f"CTI Sync failed: {str(e)}"
    finally:
        db.close()
