import json

def build_reversing_expert_prompt(case):
    static = case.analysis_results.get("static", {})
    pe_info = static.get("pe_info", {})
    strings = static.get("strings", [])
    
    prompt = f"""
# Malware Analysis Request - Reversing Expert
**File:** {case.original_filename}
**SHA256:** {case.sha256}
**Type:** {case.file_type}

## Static Analysis Context
- **Entropy:** {static.get('entropy', 'N/A')}
- **PE Sections:** {json.dumps(pe_info.get('sections', []), indent=2) if pe_info else 'N/A'}
- **Imports:** {json.dumps(pe_info.get('imports', []), indent=2) if pe_info else 'N/A'}

## YARA Matches
{json.dumps([m['rule'] for m in case.analysis_results.get('yara', {}).get('matches', [])], indent=2)}

## Strings (First 100)
{json.dumps(strings, indent=2)}

## Task
Please analyze the provided static artifacts and assembly/PE structure hints.
1. Identify potential packing or obfuscation.
2. What is the likely purpose of the imported APIs?
3. Suggest breakpoints for dynamic analysis in x64dbg.
"""
    return prompt

def build_cyber_intel_prompt(case):
    prompt = f"""
# Cyber Threat Intelligence Request
**File:** {case.original_filename}
**Hash:** {case.sha256}

## Indicators of Compromise (IOCs)
- **MD5:** {case.md5}
- **SHA256:** {case.sha256}
- **Observed Network Activity:** {json.dumps(case.analysis_results.get('dynamic', {}).get('behavior', {}).get('network', []), indent=2)}

## Task
1. Identifying this threat (Family, Actor).
2. Are there known campaigns associated with this hash or technique?
3. What are the TTPs mapped to MITRE ATT&CK?
"""
    return prompt

def build_host_countermeasures_prompt(case):
    prompt = f"""
# Host Forensics & Countermeasures Request
**File:** {case.original_filename}

## Analysis Findings
- Files created: {json.dumps(case.analysis_results.get('dynamic', {}).get('behavior', {}).get('files_created', []), indent=2)}
- Processes: {json.dumps(case.analysis_results.get('dynamic', {}).get('behavior', {}).get('processes', []), indent=2)}

## Task
1. How do I detect this on endpoints (EDR queries, Sigma rules)?
2. How do I contain the infection?
3. Removal steps?
"""
    return prompt

def build_cyber_industrial_prompt(case):
    prompt = f"""
# OT/ICS Risk Assessment Request
**File:** {case.original_filename}

## Context
Checking for specific ICS/SCADA protocol usage (Modbus, DNP3, S7) or targeted processes.

## Strings/Artifacts
{json.dumps(case.analysis_results.get('static', {}).get('strings', [])[:50], indent=2)}

## Task
1. Does this sample show intent to target industrial control systems?
2. Impact assessment for OT environment.
"""
    return prompt
