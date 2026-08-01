import pytest
import os
import sys
from fastapi.testclient import TestClient

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), "app"))

from app.main import app
from app.services.normalization import parse_raw_log_text, generate_stix_indicator

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_normalization_parsing():
    raw_firewall_log = """
    Aug  1 02:14:10 internal-firewall [CRITICAL] Inbound block from 198.51.100.42 to 192.168.1.105 on port 443
    IDS alert triggered: Signature match exploit Attempt (CVE-2021-44228) detected. Source IP: 203.0.113.195, Domain: malware-c2-portal.net
    SHA256 file threat: a12be40798ff1f66c98aa2b9d997cfbaee33440798ff1f66c98aa2b9d997cfba
    """
    
    indicators = parse_raw_log_text(raw_firewall_log)
    
    # Check that external IPs, domains, and hashes are extracted
    extracted_values = [i["value"] for i in indicators]
    
    assert "198.51.100.42" in extracted_values
    assert "203.0.113.195" in extracted_values
    assert "malware-c2-portal.net" in extracted_values
    assert "a12be40798ff1f66c98aa2b9d997cfbaee33440798ff1f66c98aa2b9d997cfba" in extracted_values
    # Check that local/RFC1918 IPs (192.168.1.105) are filtered out for safety
    assert "192.168.1.105" not in extracted_values

def test_stix_generation():
    ip_val = "198.51.100.42"
    stix_obj = generate_stix_indicator(ip_val, "ip")
    
    assert stix_obj.type == "indicator"
    assert stix_obj.spec_version == "2.1"
    assert ip_val in stix_obj.pattern
    assert "ipv4-addr" in stix_obj.pattern
    assert "indicator--" in stix_obj.id
