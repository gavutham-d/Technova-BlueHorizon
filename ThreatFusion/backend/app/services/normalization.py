import re
import uuid
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Tuple
from app.models.schemas import STIX21Indicator

# Regex patterns for IOC extraction
IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'
MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'
URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'

IP_REGEX = re.compile(IP_PATTERN)
DOMAIN_REGEX = re.compile(DOMAIN_PATTERN)
MD5_REGEX = re.compile(MD5_PATTERN)
SHA256_REGEX = re.compile(SHA256_PATTERN)
CVE_REGEX = re.compile(CVE_PATTERN)
URL_REGEX = re.compile(URL_PATTERN)

def clean_ip(ip: str) -> bool:
    # Filter out local/loopback/multicast IPs
    if ip.startswith(("127.", "0.", "10.", "192.168.")):
        return False
    if ip.startswith("172."):
        try:
            parts = ip.split('.')
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return False
        except Exception:
            pass
    return True

def generate_stix_indicator(ioc_value: str, ioc_type: str) -> STIX21Indicator:
    """
    Generates a valid STIX 2.1 representation of a threat indicator.
    """
    uuid_val = str(uuid.uuid4())
    indicator_id = f"indicator--{uuid_val}"
    
    # Formulate STIX pattern
    if ioc_type == "ip":
        pattern = f"[ipv4-addr:value = '{ioc_value}']"
        labels = ["malicious-activity", "compromised-ip"]
    elif ioc_type == "domain":
        pattern = f"[domain-name:value = '{ioc_value}']"
        labels = ["malicious-activity", "phishing-domain"]
    elif ioc_type == "hash":
        pattern = f"[file:hashes.SHA-256 = '{ioc_value}']" if len(ioc_value) == 64 else f"[file:hashes.MD5 = '{ioc_value}']"
        labels = ["malicious-activity", "malware-sample"]
    elif ioc_type == "url":
        pattern = f"[url:value = '{ioc_value}']"
        labels = ["malicious-activity", "phishing-url"]
    else:
        pattern = f"[file:name = '{ioc_value}']"
        labels = ["suspicious-file"]
        
    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    return STIX21Indicator(
        id=indicator_id,
        pattern=pattern,
        valid_from=now_str,
        created=now_str,
        modified=now_str,
        labels=labels,
        indicator_types=["malicious-activity"]
    )

def parse_raw_log_text(text: str) -> List[Dict[str, Any]]:
    """
    Extracts IPs, Domains, Hashes, and URLs from raw text (Firewall, IDS, SIEM logs).
    """
    indicators = []
    
    # 1. Extract IPs
    ips = list(set(IP_REGEX.findall(text)))
    for ip in ips:
        if clean_ip(ip):
            indicators.append({
                "value": ip,
                "ioc_type": "ip",
                "description": "Extracted IP from log stream"
            })
            
    # 2. Extract Domains
    domains = list(set(DOMAIN_REGEX.findall(text)))
    for dom in domains:
        # Avoid common extensions/system domains
        if not dom.endswith((".local", ".lan", ".arpa", "in-addr.arpa", "localdomain", "localhost")):
            indicators.append({
                "value": dom,
                "ioc_type": "domain",
                "description": "Extracted Domain from log stream"
            })
            
    # 3. Extract Hashes
    md5s = list(set(MD5_REGEX.findall(text)))
    for m in md5s:
        indicators.append({
            "value": m.lower(),
            "ioc_type": "hash",
            "description": "Extracted MD5 hash from log stream"
        })
        
    sha256s = list(set(SHA256_REGEX.findall(text)))
    for s in sha256s:
        indicators.append({
            "value": s.lower(),
            "ioc_type": "hash",
            "description": "Extracted SHA256 hash from log stream"
        })
        
    # 4. Extract URLs
    urls = list(set(URL_REGEX.findall(text)))
    for u in urls:
        indicators.append({
            "value": u,
            "ioc_type": "url",
            "description": "Extracted URL from log stream"
        })
        
    return indicators

def parse_structured_file(file_path: str, filename: str) -> List[Dict[str, Any]]:
    """
    Parses CSV, JSON, and Excel documents.
    """
    indicators = []
    
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(file_path)
        elif filename.endswith((".xls", ".xlsx")):
            df = pd.read_excel(file_path)
        elif filename.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = pd.DataFrame([data])
        else:
            # Try parsing as raw text if format is unknown
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
            return parse_raw_log_text(content)
            
        # Clean column names
        df.columns = [c.lower().strip() for c in df.columns]
        
        # Look for headers containing indicator patterns
        val_cols = [c for c in df.columns if any(p in c for p in ["value", "indicator", "ioc", "ip", "domain", "hash", "url"])]
        type_cols = [c for c in df.columns if any(p in c for p in ["type", "ioc_type", "kind"])]
        desc_cols = [c for c in df.columns if any(p in c for p in ["desc", "info", "reason", "comment"])]
        cve_cols = [c for c in df.columns if "cve" in c]
        mal_cols = [c for c in df.columns if "malware" in c]
        
        for _, row in df.iterrows():
            ioc_val = ""
            # Get value
            if val_cols:
                ioc_val = str(row[val_cols[0]]).strip()
            else:
                # If no clear column, search raw string of row
                row_str = " ".join([str(v) for v in row.values])
                extracted = parse_raw_log_text(row_str)
                if extracted:
                    indicators.extend(extracted)
                continue
                
            if not ioc_val or ioc_val == "nan" or ioc_val == "None":
                continue
                
            # Determine type
            ioc_type = "ip"
            if type_cols:
                raw_type = str(row[type_cols[0]]).lower().strip()
                if "domain" in raw_type:
                    ioc_type = "domain"
                elif "hash" in raw_type or "md5" in raw_type or "sha" in raw_type:
                    ioc_type = "hash"
                elif "url" in raw_type:
                    ioc_type = "url"
            else:
                # Infer type
                if IP_REGEX.match(ioc_val):
                    ioc_type = "ip"
                elif SHA256_REGEX.match(ioc_val) or MD5_REGEX.match(ioc_val):
                    ioc_type = "hash"
                elif ioc_val.startswith(("http://", "https://")):
                    ioc_type = "url"
                else:
                    ioc_type = "domain"
                    
            desc = str(row[desc_cols[0]]) if desc_cols else f"Parsed from {filename}"
            cves = []
            if cve_cols:
                raw_cves = str(row[cve_cols[0]])
                if raw_cves and raw_cves != "nan":
                    cves = [c.strip() for c in CVE_REGEX.findall(raw_cves)]
            malware = []
            if mal_cols:
                raw_mal = str(row[mal_cols[0]])
                if raw_mal and raw_mal != "nan":
                    malware = [m.strip() for m in raw_mal.split(",") if m.strip()]
                    
            indicators.append({
                "value": ioc_val,
                "ioc_type": ioc_type,
                "description": desc,
                "associated_cves": cves,
                "associated_malware": malware
            })
            
    except Exception as e:
        # Fallback to raw text extraction on exception
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
            return parse_raw_log_text(content)
        except Exception:
            pass
            
    return indicators
