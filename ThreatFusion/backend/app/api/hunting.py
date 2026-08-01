from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from app.database import audit_logs_collection, indicators_collection
from app.models.schemas import UserRole
from app.api.auth import get_current_user, RoleChecker
from app.services.ml_pipeline import detect_log_anomaly

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])

read_guard = RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.READ_ONLY])

@router.get("/anomalies", response_model=List[Dict[str, Any]])
async def check_anomalies(current_user: dict = Depends(read_guard)):
    """
    Simulates checking current platform request patterns/volumes against Isolation Forest
    and returns logs that represent security anomalies.
    """
    cursor = audit_logs_collection.find({}).sort("timestamp", -1).limit(100)
    logs = await cursor.to_list(length=100)
    
    anomalous_events = []
    
    # Process each log to evaluate anomalies
    for l in logs:
        # Standardize size metric (using action string lengths)
        time_hour = l["timestamp"].hour
        byte_size = len(l["action"]) * 10
        
        # Test using Isolation Forest
        is_anom, score = detect_log_anomaly(
            request_count=1,
            hour_of_day=time_hour,
            log_byte_size=byte_size
        )
        
        if is_anom or score < 0.05: # decision score threshold
            anomalous_events.append({
                "log_id": str(l["_id"]),
                "username": l["username"],
                "action": l["action"],
                "ip_address": l["ip_address"],
                "timestamp": l["timestamp"],
                "anomaly_score": round(abs(score) * 100, 1),
                "reason": "Abnormal activity hour or packet size" if time_hour < 6 or time_hour > 22 else "Outlier request attributes"
            })
            
    # Mock data fallback for demonstration if no DB logs yet
    if not anomalous_events:
        anomalous_events = [
            {
                "log_id": "audit--0ff321-anomaly",
                "username": "unknown_scan_bot",
                "action": "PORT_SCAN_EXPLORE",
                "ip_address": "45.143.203.14",
                "timestamp": "2026-08-01T02:14:10Z",
                "anomaly_score": 87.2,
                "reason": "Off-hours system scan spike"
            },
            {
                "log_id": "audit--9aa765-anomaly",
                "username": "analyst_guest",
                "action": "BULK_THREAT_EXPORT_10000_RECORDS",
                "ip_address": "80.94.95.120",
                "timestamp": "2026-08-01T23:55:00Z",
                "anomaly_score": 91.5,
                "reason": "Suspicious exfiltration volume spike"
            }
        ]
        
    return anomalous_events

@router.post("/test-log")
async def test_single_log(
    request_count: int,
    hour_of_day: int,
    log_byte_size: int,
    current_user: dict = Depends(read_guard)
):
    """
    Evaluates raw variables against Isolation Forest to classify log safety.
    """
    is_anomaly, score = detect_log_anomaly(request_count, hour_of_day, log_byte_size)
    return {
        "is_anomaly": is_anomaly,
        "score": float(round(score, 4)),
        "risk_level": "High/Critical" if is_anomaly else "Normal",
        "description": "Log pattern represents an outlier in system behavior." if is_anomaly else "Log pattern matches normal operational baseline."
    }
