from app.analysis import static_analysis, dynamic_analysis, yara_scanner
from app.storage import db
import json

def calculate_risk_score(static_results, dynamic_results, yara_results):
    score = 0
    
    # YARA matches (High Impact)
    yara_matches = yara_results.get("matches", [])
    if yara_matches:
        score += len(yara_matches) * 20  # +20 per match
        
    # Static factors
    if static_results.get("entropy", 0) > 7.0:
        score += 20
        
    pe_info = static_results.get("pe_info", {})
    if pe_info and "error" not in pe_info:
        # Check for suspicious imports (simplified)
        suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
        for imp in pe_info.get("imports", []):
            for func in imp.get("functions", []):
                if func in suspicious_apis:
                    score += 10

    # Dynamic factors
    behavior = dynamic_results.get("behavior", {})
    if behavior.get("network"):
        score += 30
    if behavior.get("processes"):
        score += 20
        
    return min(score, 100)

def run_analysis_pipeline(case):
    # Update status
    db.update_case_status(case.id, "analyzing")
    
    # Run Static
    static_res = static_analysis.run_static_analysis(case)
    
    # Run YARA
    yara_res = yara_scanner.run_yara_scan(case)
    
    # Run Dynamic
    dynamic_res = dynamic_analysis.run_dynamic_analysis(case)
    
    # Consolidate
    full_results = {
        "static": static_res,
        "yara": yara_res,
        "dynamic": dynamic_res
    }
    
    case.analysis_results = full_results
    
    # Risk Score
    risk_score = calculate_risk_score(static_res, dynamic_res, yara_res)
    case.risk_score = risk_score
    
    # Update DB
    db.update_case_status(case.id, "completed", risk_score, full_results)
    
    # Store simple artifacts
    if "entropy" in static_res:
         db.add_artifact(case.id, "metric", str(static_res["entropy"]), "Entropy")
         
    if yara_res.get("matches"):
        for m in yara_res["matches"]:
            db.add_artifact(case.id, "yara_match", m['rule'], "YARA Rule Match")
         
    return case
