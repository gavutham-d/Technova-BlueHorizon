import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import DBSCAN
import xgboost as xgb
import logging
from typing import Dict, List, Any, Tuple, Optional

logger = logging.getLogger(__name__)

# Global model pointers
rf_model = None
iforest_model = None
dbscan_model = None
xgboost_model = None

# Performance cache for DBSCAN transductive lookup
dbscan_train_coords = None
dbscan_labels = None

# In-memory database of campaign cluster information
campaign_names_map = {
    -1: "Unassociated Scans / General Activity",
    0: "Operation CyberShield (APT-39 Simulated)",
    1: "LockBit 4.0 Campaign Group",
    2: "Phishing Wave: AgentTesla Distribution",
    3: "Log4Shell Exploitation Sweep"
}

# IOC Type mapping
IOC_TYPE_MAP = {"ip": 0, "domain": 1, "hash": 2, "url": 3}

def generate_synthetic_threat_data(n_samples: int = 200) -> pd.DataFrame:
    """
    Generates a high-quality synthetic threat database for initial model training.
    """
    np.random.seed(42)
    
    cvss = np.random.uniform(0.0, 10.0, n_samples)
    confidence = np.random.uniform(30.0, 100.0, n_samples)
    source_count = np.random.randint(1, 15, n_samples)
    days_active = np.random.randint(1, 90, n_samples)
    subnet_malicious = np.random.choice([0, 1], size=n_samples, p=[0.8, 0.2])
    ioc_type = np.random.choice([0, 1, 2, 3], size=n_samples) # ip, domain, hash, url
    
    # Generate risk scores (0 to 100) based on logic with some noise
    base_risk = (cvss * 4.0) + (confidence * 0.3) + (source_count * 1.5) + (subnet_malicious * 15.0)
    risk_scores = np.clip(base_risk + np.random.normal(0, 5, n_samples), 0, 100)
    
    # Generate severity classes: 0 (Low), 1 (Medium), 2 (High), 3 (Critical)
    severity_classes = []
    for r in risk_scores:
        if r < 35:
            severity_classes.append(0) # Low
        elif r < 65:
            severity_classes.append(1) # Medium
        elif r < 85:
            severity_classes.append(2) # High
        else:
            severity_classes.append(3) # Critical
            
    df = pd.DataFrame({
        "cvss_score": cvss,
        "feed_confidence": confidence,
        "source_count": source_count,
        "days_active": days_active,
        "ip_in_malicious_subnet": subnet_malicious,
        "ioc_type_encoded": ioc_type,
        "risk_score": risk_scores,
        "severity": severity_classes
    })
    
    return df

def generate_synthetic_audit_data(n_samples: int = 150) -> pd.DataFrame:
    """
    Generates logs data for Anomaly Detection (Isolation Forest).
    Features: [request_count, time_of_day_hour, log_byte_size]
    """
    np.random.seed(42)
    
    # Normal traffic
    norm_requests = np.random.randint(5, 50, int(n_samples * 0.95))
    norm_hours = np.random.randint(8, 18, int(n_samples * 0.95)) # Office hours
    norm_bytes = np.random.randint(200, 2000, int(n_samples * 0.95))
    
    # Anomalous traffic (midnight spikes, huge byte transfers, high query frequencies)
    anom_requests = np.random.randint(300, 1000, int(n_samples * 0.05))
    anom_hours = np.random.choice([0, 1, 2, 3, 22, 23], size=int(n_samples * 0.05))
    anom_bytes = np.random.randint(50000, 1000000, int(n_samples * 0.05))
    
    requests = np.concatenate([norm_requests, anom_requests])
    hours = np.concatenate([norm_hours, anom_hours])
    sizes = np.concatenate([norm_bytes, anom_bytes])
    
    return pd.DataFrame({
        "request_count": requests,
        "hour_of_day": hours,
        "log_byte_size": sizes
    })

def initialize_ml_models():
    """
    Trains and initializes models on synthetic CTI logs so the SOC dashboard works on launch.
    """
    global rf_model, iforest_model, dbscan_model, xgboost_model
    logger.info("Training ML models with synthetic seed datasets...")
    
    df_cti = generate_synthetic_threat_data(250)
    df_audit = generate_synthetic_audit_data(200)
    
    # 1. Random Forest (Severity classification)
    X_rf = df_cti[["cvss_score", "feed_confidence", "source_count", "days_active", "ip_in_malicious_subnet", "ioc_type_encoded"]]
    y_rf = df_cti["severity"]
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf_model.fit(X_rf, y_rf)
    
    # 2. Isolation Forest (Log Anomaly Detection)
    X_if = df_audit[["request_count", "hour_of_day", "log_byte_size"]]
    iforest_model = IsolationForest(contamination=0.05, random_state=42)
    iforest_model.fit(X_if)
    
    # 3. DBSCAN (Campaign Clustering)
    X_dbscan = df_cti[["risk_score", "cvss_score", "feed_confidence"]]
    # Scale variables manually for simplification
    dbscan_model = DBSCAN(eps=15.0, min_samples=3)
    dbscan_model.fit(X_dbscan)
    
    global dbscan_train_coords, dbscan_labels
    dbscan_train_coords = X_dbscan.values
    dbscan_labels = dbscan_model.labels_
    
    # 4. XGBoost (Risk score regression)
    X_xgb = df_cti[["cvss_score", "feed_confidence", "source_count", "days_active", "ip_in_malicious_subnet"]]
    y_xgb = df_cti["risk_score"]
    
    xgboost_model = xgb.XGBRegressor(n_estimators=80, max_depth=4, learning_rate=0.1, random_state=42)
    xgboost_model.fit(X_xgb, y_xgb)
    
    logger.info("Machine learning pipeline initialized successfully.")

def predict_risk_score(cvss_score: float, feed_confidence: float, source_count: int, days_active: int, ip_in_malicious_subnet: bool) -> float:
    """
    Predicts XGBoost Threat Risk Score (0-100).
    """
    global xgboost_model
    if xgboost_model is None:
        initialize_ml_models()
        
    X = np.array([[
        cvss_score,
        feed_confidence,
        source_count,
        days_active,
        1.0 if ip_in_malicious_subnet else 0.0
    ]])
    pred = float(xgboost_model.predict(X)[0])
    return float(np.clip(pred, 0.0, 100.0))

def predict_severity(cvss_score: float, feed_confidence: float, source_count: int, days_active: int, ip_in_malicious_subnet: bool, ioc_type: str) -> str:
    """
    Predicts threat severity using Random Forest model.
    """
    global rf_model
    if rf_model is None:
        initialize_ml_models()
        
    ioc_encoded = IOC_TYPE_MAP.get(ioc_type.lower(), 0)
    X = np.array([[
        cvss_score,
        feed_confidence,
        source_count,
        days_active,
        1.0 if ip_in_malicious_subnet else 0.0,
        ioc_encoded
    ]])
    pred_class = int(rf_model.predict(X)[0])
    severities = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
    return severities.get(pred_class, "Low")

def detect_log_anomaly(request_count: int, hour_of_day: int, log_byte_size: int) -> Tuple[bool, float]:
    """
    Detects logs/request anomaly using Isolation Forest.
    Returns: (is_anomaly, decision_score)
    """
    global iforest_model
    if iforest_model is None:
        initialize_ml_models()
        
    X = np.array([[request_count, hour_of_day, log_byte_size]])
    prediction = iforest_model.predict(X)[0] # 1 = normal, -1 = anomaly
    score = float(iforest_model.decision_function(X)[0])
    return (prediction == -1, score)

def assign_campaign_cluster(risk_score: float, cvss_score: float, feed_confidence: float) -> Tuple[int, str]:
    """
    Uses DBSCAN rules/parameters to allocate a threat indicators cluster (campaign).
    Since DBSCAN is transductive (no predict() function), we evaluate Euclidean distance 
    to the training set to classify new points.
    """
    global dbscan_model, dbscan_train_coords, dbscan_labels
    if dbscan_model is None or dbscan_train_coords is None or dbscan_labels is None:
        initialize_ml_models()
        
    # Calculate distance to all training coordinates
    point = np.array([risk_score, cvss_score, feed_confidence])
    distances = np.linalg.norm(dbscan_train_coords - point, axis=1)
    
    min_dist_idx = np.argmin(distances)
    if distances[min_dist_idx] < 15.0:
        cluster_id = int(dbscan_labels[min_dist_idx])
    else:
        cluster_id = -1
        
    campaign_name = campaign_names_map.get(cluster_id, "Unknown Operation Group")
    return cluster_id, campaign_name

def retrain_pipeline_with_data(indicators: List[Dict[str, Any]], audit_logs: List[Dict[str, Any]]):
    """
    Triggers model updates based on live databases.
    """
    global rf_model, iforest_model, dbscan_model, xgboost_model
    
    logger.info(f"Retraining models with {len(indicators)} indicators and {len(audit_logs)} logs...")
    
    # 1. Rebuild Indicator features
    cti_records = []
    for ind in indicators:
        cvss = ind.get("cvss_score") or 5.0
        conf = ind.get("feed_confidence") or 80.0
        src_c = ind.get("source_count") or 1
        days_a = ind.get("days_active") or 1
        sub_m = 1.0 if ind.get("ip_in_malicious_subnet") else 0.0
        ioc_enc = IOC_TYPE_MAP.get(ind.get("ioc_type", "ip"), 0)
        risk = ind.get("risk_score") or 50.0
        
        sev_map = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        sev = sev_map.get(ind.get("severity", "Low"), 0)
        
        cti_records.append([cvss, conf, src_c, days_a, sub_m, ioc_enc, risk, sev])
        
    if len(cti_records) >= 10:
        df_cti = pd.DataFrame(cti_records, columns=["cvss_score", "feed_confidence", "source_count", "days_active", "ip_in_malicious_subnet", "ioc_type_encoded", "risk_score", "severity"])
    else:
        # Fallback to seed + new records
        df_cti = generate_synthetic_threat_data(200)
        
    # 2. Rebuild Log features
    log_records = []
    for log in audit_logs:
        # Standardize size/timing variables
        timestamp = log.get("timestamp")
        hour = timestamp.hour if hasattr(timestamp, 'hour') else 12
        action_len = len(log.get("action", ""))
        log_records.append([1, hour, action_len * 10])
        
    if len(log_records) >= 10:
        df_audit = pd.DataFrame(log_records, columns=["request_count", "hour_of_day", "log_byte_size"])
    else:
        df_audit = generate_synthetic_audit_data(100)
        
    # Refit
    X_rf = df_cti[["cvss_score", "feed_confidence", "source_count", "days_active", "ip_in_malicious_subnet", "ioc_type_encoded"]]
    y_rf = df_cti["severity"]
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf_model.fit(X_rf, y_rf)
    
    X_if = df_audit[["request_count", "hour_of_day", "log_byte_size"]]
    iforest_model = IsolationForest(contamination=0.05, random_state=42)
    iforest_model.fit(X_if)
    
    X_dbscan = df_cti[["risk_score", "cvss_score", "feed_confidence"]]
    dbscan_model = DBSCAN(eps=15.0, min_samples=3)
    dbscan_model.fit(X_dbscan)
    
    global dbscan_train_coords, dbscan_labels
    dbscan_train_coords = X_dbscan.values
    dbscan_labels = dbscan_model.labels_
    
    X_xgb = df_cti[["cvss_score", "feed_confidence", "source_count", "days_active", "ip_in_malicious_subnet"]]
    y_xgb = df_cti["risk_score"]
    xgboost_model = xgb.XGBRegressor(n_estimators=80, max_depth=4, learning_rate=0.1, random_state=42)
    xgboost_model.fit(X_xgb, y_xgb)
    
    logger.info("All machine learning models retrained successfully.")
