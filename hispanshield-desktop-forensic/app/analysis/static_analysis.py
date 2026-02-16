import os
import math
import collections
import re
import json

try:
    import pefile
except ImportError:
    pefile = None

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_strings(data, min_length=4):
    result = ""
    # Regex for ASCII strings
    chars = b"[\x20-\x7E]"
    regexp = b"(%s{%d,})" % (chars, min_length)
    pattern = re.compile(regexp)
    
    strings = []
    for match in pattern.finditer(data):
        try:
            strings.append(match.group(0).decode("ascii"))
        except:
            pass
            
    # Limit validation to first 100 strings
    return strings[:100]

def analyze_pe(file_path):
    if not pefile:
        return {"error": "pefile library not installed"}
        
    try:
        pe = pefile.PE(file_path)
        info = {
            "imphash": pe.get_imphash(),
            "compilation_timestamp": pe.FILE_HEADER.TimeDateStamp,
            "sections": [],
            "imports": []
        }
        
        for section in pe.sections:
            info["sections"].append({
                "name": section.Name.decode().strip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy()
            })
            
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().strip()
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode().strip())
                info["imports"].append({
                    "dll": dll_name,
                    "functions": functions[:10] # Limit to 10 functions per DLL
                })
                
        return info
    except Exception as e:
        return {"error": f"PE Parsing failed: {str(e)}"}

def run_static_analysis(case):
    results = {}
    file_path = case.file_path
    
    if not os.path.exists(file_path):
        return {"error": "File not found"}
        
    with open(file_path, "rb") as f:
        data = f.read()
        
    # Global Entropy
    results["entropy"] = calculate_entropy(data)
    
    # Strings
    results["strings"] = extract_strings(data)
    
    # PE Analysis if applicable
    if case.file_path.lower().endswith(".exe") or case.file_path.lower().endswith(".dll"):
        results["pe_info"] = analyze_pe(file_path)
        
    return results
