import httpx
import random
import logging
from typing import List, Dict, Any, Optional
from app.config import settings

logger = logging.getLogger(__name__)

# Static lookup mapping for MITRE ATT&CK techniques
MITRE_MAPPINGS = {
    "ip": [
        "T1071.001 - Command and Control: Web Protocols",
        "T1090.003 - Proxy: Multi-hop Proxy",
        "T1568.002 - Dynamic Resolution: Domain Generation Algorithms",
        "T1105 - Ingress Tool Transfer"
    ],
    "domain": [
        "T1566.002 - Phishing: Spearphishing Link",
        "T1071.001 - Command and Control: Web Protocols",
        "T1568 - Dynamic Resolution"
    ],
    "hash": [
        "T1204.002 - User Execution: Malicious File",
        "T1059.001 - Command and Scripting Interpreter: PowerShell",
        "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "T1027 - Obfuscated Files or Information"
    ],
    "url": [
        "T1566.001 - Phishing: Spearphishing Attachment",
        "T1566.002 - Phishing: Spearphishing Link",
        "T1204.001 - User Execution: Malicious Link"
    ]
}

# Static lookup mapping for CVE CVSS scores
CVE_CVSS_MAP = {
    "CVE-2021-44228": 10.0, # Log4Shell
    "CVE-2023-38831": 7.8,  # WinRAR
    "CVE-2024-3094": 10.0,  # XZ Utils Backdoor
    "CVE-2022-30190": 7.8,  # Follina
    "CVE-2023-3519": 9.8,   # Citrix ADC
    "CVE-2021-34473": 9.8,  # ProxyShell
    "CVE-2020-1472": 10.0,  # ZeroLogon
}

def get_mitre_techniques(ioc_type: str, seed: Optional[str] = None) -> List[str]:
    """
    Returns a consistent list of MITRE ATT&CK techniques mapping to the IOC type.
    """
    options = MITRE_MAPPINGS.get(ioc_type.lower(), ["T1071 - Command and Control: Application Layer Protocol"])
    # Seed random selection to keep it deterministic per indicator
    if seed:
        random.seed(seed)
    else:
        random.seed(ioc_type)
    count = random.randint(1, min(len(options), 2))
    return random.sample(options, count)

def calculate_cvss_score(cves: List[str]) -> Optional[float]:
    """
    Calculates CVSS score by taking the max score of the associated CVEs, or defaults to None.
    """
    if not cves:
        return None
    scores = [CVE_CVSS_MAP.get(cve.upper(), 5.0 + (hash(cve) % 50) / 10.0) for cve in cves]
    return max(scores) if scores else None

async def enrich_ioc(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Enriches the indicator using external services (or simulations if keys are absent).
    """
    enrichment_data = {
        "source_count": 1,
        "feed_confidence": 75.0,
        "days_active": 1,
        "mitre_techniques": get_mitre_techniques(ioc_type, value),
        "associated_malware": [],
        "associated_cves": [],
        "cvss_score": None,
        "ip_in_malicious_subnet": False
    }

    # Extract seed values for deterministic mocks
    val_hash = abs(hash(value))
    
    # Standard Mock / Simulated Enrichment
    enrichment_data["feed_confidence"] = float(60 + (val_hash % 41))
    enrichment_data["source_count"] = 1 + (val_hash % 5)
    enrichment_data["days_active"] = 1 + (val_hash % 60)
    
    if ioc_type == "ip":
        enrichment_data["ip_in_malicious_subnet"] = (val_hash % 7 == 0)
        
    # Mock Malware Association
    malware_options = ["Cobalt Strike", "LockBit", "AgentTesla", "RedLine", "Qakbot", "Emotet", "NjRAT", "GuLoader"]
    if val_hash % 3 == 0:
        enrichment_data["associated_malware"] = [malware_options[val_hash % len(malware_options)]]
        
    # Mock CVE Association
    cve_options = list(CVE_CVSS_MAP.keys())
    if val_hash % 5 == 0:
        enrichment_data["associated_cves"] = [cve_options[val_hash % len(cve_options)]]
        enrichment_data["cvss_score"] = calculate_cvss_score(enrichment_data["associated_cves"])

    # Attempt Real Enrichment if API key exists (e.g. AbuseIPDB)
    if ioc_type == "ip" and settings.ABUSEIPDB_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                headers = {
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": value,
                    "maxAgeInDays": "90"
                }
                response = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    enrichment_data["feed_confidence"] = float(data.get("abuseConfidenceScore", enrichment_data["feed_confidence"]))
                    enrichment_data["source_count"] = max(enrichment_data["source_count"], data.get("totalReports", 1))
                    logger.info(f"Enriched {value} using AbuseIPDB. Score: {enrichment_data['feed_confidence']}")
        except Exception as e:
            logger.warning(f"Failed to query AbuseIPDB for {value}: {str(e)}")

    # Add default description if empty
    if not enrichment_data["associated_malware"]:
        if ioc_type == "ip":
            enrichment_data["associated_malware"] = ["Unknown Agent"]
        elif ioc_type == "hash":
            enrichment_data["associated_malware"] = ["Trojan.Generic"]
        else:
            enrichment_data["associated_malware"] = ["Adware.Suspicious"]

    return enrichment_data
