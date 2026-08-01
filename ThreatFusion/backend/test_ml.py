import pytest
import os
import sys

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), "app"))

from app.services.ml_pipeline import (
    initialize_ml_models,
    predict_risk_score,
    predict_severity,
    detect_log_anomaly,
    assign_campaign_cluster
)

@pytest.fixture(scope="module", autouse=True)
def setup_models():
    initialize_ml_models()

def test_risk_score_prediction():
    # Test High/Critical inputs
    high_risk = predict_risk_score(
        cvss_score=9.8,
        feed_confidence=95.0,
        source_count=8,
        days_active=10,
        ip_in_malicious_subnet=True
    )
    assert 70.0 <= high_risk <= 100.0
    
    # Test Low inputs
    low_risk = predict_risk_score(
        cvss_score=1.5,
        feed_confidence=40.0,
        source_count=1,
        days_active=1,
        ip_in_malicious_subnet=False
    )
    assert 0.0 <= low_risk <= 45.0

def test_severity_classification():
    critical_sev = predict_severity(
        cvss_score=10.0,
        feed_confidence=99.0,
        source_count=12,
        days_active=15,
        ip_in_malicious_subnet=True,
        ioc_type="ip"
    )
    assert critical_sev in ["High", "Critical"]
    
    low_sev = predict_severity(
        cvss_score=1.0,
        feed_confidence=30.0,
        source_count=1,
        days_active=1,
        ip_in_malicious_subnet=False,
        ioc_type="url"
    )
    assert low_sev in ["Low", "Medium"]

def test_log_anomaly_detection():
    # Normal day-time log, small size
    is_anomaly, score = detect_log_anomaly(
        request_count=10,
        hour_of_day=14,
        log_byte_size=500
    )
    assert not is_anomaly
    
    # Abnormal midnight surge, huge byte size
    is_anomaly_anom, score_anom = detect_log_anomaly(
        request_count=900,
        hour_of_day=2,
        log_byte_size=800000
    )
    assert is_anomaly_anom

def test_campaign_clustering():
    cluster_id, name = assign_campaign_cluster(
        risk_score=95.0,
        cvss_score=9.8,
        feed_confidence=98.0
    )
    # Check that it either maps to Operation CyberShield or another cluster, or maps to noise group
    assert name is not None
    assert isinstance(cluster_id, int)
