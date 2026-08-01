from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request
from typing import List, Optional, Dict, Any
from app.database import indicators_collection, alerts_collection
from app.models.schemas import IndicatorResponse, IndicatorCreate, UserRole
from app.api.auth import get_current_user, RoleChecker, log_audit_action
from app.services.cache_manager import cache_store
from app.services.normalization import parse_structured_file, parse_raw_log_text, generate_stix_indicator
from app.services.enrichment import enrich_ioc
from app.services.ml_pipeline import predict_risk_score, predict_severity, assign_campaign_cluster
import os
import shutil
import tempfile
from datetime import datetime
import uuid

router = APIRouter(prefix="/indicators", tags=["Indicators"])

# RBAC guards
write_guard = RoleChecker([UserRole.ADMIN, UserRole.ANALYST])
read_guard = RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.READ_ONLY])

@router.get("", response_model=Dict[str, Any])
async def list_indicators(
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    current_user: dict = Depends(read_guard)
):
    query = {}
    
    if search:
        query["value"] = {"$regex": search, "$options": "i"}
    if ioc_type:
        query["ioc_type"] = ioc_type
    if severity:
        query["severity"] = severity
    if source:
        query["source"] = source
        
    skip = (page - 1) * limit
    total = await indicators_collection.count_documents(query)
    
    cursor = indicators_collection.find(query).skip(skip).limit(limit).sort("created_at", -1)
    results = await cursor.to_list(length=limit)
    
    # Format results
    formatted_results = []
    for doc in results:
        doc["_id"] = str(doc["_id"])
        formatted_results.append(doc)
        
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "indicators": formatted_results
    }

@router.post("", response_model=IndicatorResponse)
async def create_indicator(
    payload: IndicatorCreate,
    request: Request,
    current_user: dict = Depends(write_guard)
):
    # Check if exists
    existing = await indicators_collection.find_one({"value": payload.value})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Indicator already exists in the intelligence repository."
        )
        
    # Perform enrichment
    enrichment = await enrich_ioc(payload.value, payload.ioc_type)
    
    # Merge custom payloads if specified
    associated_cves = list(set(payload.associated_cves + enrichment["associated_cves"]))
    associated_malware = list(set(payload.associated_malware + enrichment["associated_malware"]))
    
    cvss_score = enrichment["cvss_score"]
    if cvss_score is None and associated_cves:
        from app.services.enrichment import calculate_cvss_score
        cvss_score = calculate_cvss_score(associated_cves)
        
    # Run ML pipelines
    risk_score = predict_risk_score(
        cvss_score=cvss_score or 5.0,
        feed_confidence=enrichment["feed_confidence"],
        source_count=enrichment["source_count"],
        days_active=enrichment["days_active"],
        ip_in_malicious_subnet=enrichment["ip_in_malicious_subnet"]
    )
    
    severity = predict_severity(
        cvss_score=cvss_score or 5.0,
        feed_confidence=enrichment["feed_confidence"],
        source_count=enrichment["source_count"],
        days_active=enrichment["days_active"],
        ip_in_malicious_subnet=enrichment["ip_in_malicious_subnet"],
        ioc_type=payload.ioc_type
    )
    
    cluster_id, campaign_name = assign_campaign_cluster(
        risk_score=risk_score,
        cvss_score=cvss_score or 5.0,
        feed_confidence=enrichment["feed_confidence"]
    )
    
    # STIX
    stix = generate_stix_indicator(payload.value, payload.ioc_type)
    
    doc = {
        "_id": stix.id,
        "value": payload.value,
        "ioc_type": payload.ioc_type,
        "source": payload.source,
        "description": payload.description or f"Manually created indicator by {current_user['username']}",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "severity": severity,
        "risk_score": risk_score,
        "feed_confidence": enrichment["feed_confidence"],
        "source_count": enrichment["source_count"],
        "days_active": enrichment["days_active"],
        "ip_in_malicious_subnet": enrichment["ip_in_malicious_subnet"],
        "status": "active",
        "mitre_techniques": enrichment["mitre_techniques"],
        "associated_malware": associated_malware,
        "associated_cves": associated_cves,
        "cvss_score": cvss_score,
        "campaign_id": campaign_name if cluster_id != -1 else None,
        "stix_representation": stix.dict()
    }
    
    await indicators_collection.insert_one(doc)
    cache_store.invalidate("dashboard_metrics")
    
    # Audit log
    await log_audit_action(current_user["username"], current_user["role"], "INDICATOR_CREATE", doc["_id"], "SUCCESS", request)
    
    # Threat alerting
    if risk_score >= 80.0:
        alert_id = f"alert--{str(uuid.uuid4())[:8]}"
        alert_doc = {
            "_id": alert_id,
            "indicator_value": payload.value,
            "ioc_type": payload.ioc_type,
            "severity": severity,
            "risk_score": risk_score,
            "trigger_reason": f"Manual creation of highly critical IOC: {payload.value}",
            "status": "Unassigned",
            "assigned_to": None,
            "created_at": datetime.utcnow(),
            "resolved_at": None,
            "resolution_notes": None
        }
        await alerts_collection.insert_one(alert_doc)
        
    return doc

@router.get("/{id}", response_model=IndicatorResponse)
async def get_indicator(id: str, current_user: dict = Depends(read_guard)):
    doc = await indicators_collection.find_one({"_id": id})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_BAD_REQUEST,
            detail="Threat indicator not found."
        )
    doc["_id"] = str(doc["_id"])
    return doc

@router.post("/upload")
async def upload_log_file(
    request: Request,
    file: UploadFile = File(...),
    log_type: str = Form("CSV"), # CSV, Firewall, IDS, SIEM, Antivirus, Excel, JSON
    current_user: dict = Depends(write_guard)
):
    filename = file.filename
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, filename)
    
    try:
        # Save temp file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        parsed_iocs = []
        if log_type in ["CSV", "Excel", "JSON"]:
            parsed_iocs = parse_structured_file(file_path, filename)
        else:
            # Parse raw text log
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
            parsed_iocs = parse_raw_log_text(content)
            
        # Import into MongoDB
        imported_count = 0
        duplicate_count = 0
        alert_count = 0
        
        for ioc in parsed_iocs:
            val = ioc["value"]
            ioc_type = ioc["ioc_type"]
            desc = ioc.get("description", f"Extracted from {filename} ({log_type} Log)")
            associated_cves = ioc.get("associated_cves", [])
            associated_malware = ioc.get("associated_malware", [])
            
            existing = await indicators_collection.find_one({"value": val})
            if existing:
                duplicate_count += 1
                # Increment source counts or update times
                await indicators_collection.update_one(
                    {"_id": existing["_id"]},
                    {"$inc": {"source_count": 1}, "$set": {"updated_at": datetime.utcnow()}}
                )
                continue
                
            # Perform ML & normalizations
            enrichment = await enrich_ioc(val, ioc_type)
            all_cves = list(set(associated_cves + enrichment["associated_cves"]))
            all_malware = list(set(associated_malware + enrichment["associated_malware"]))
            
            cvss_score = enrichment["cvss_score"]
            if cvss_score is None and all_cves:
                from app.services.enrichment import calculate_cvss_score
                cvss_score = calculate_cvss_score(all_cves)
                
            risk_score = predict_risk_score(
                cvss_score=cvss_score or 5.0,
                feed_confidence=enrichment["feed_confidence"],
                source_count=enrichment["source_count"],
                days_active=enrichment["days_active"],
                ip_in_malicious_subnet=enrichment["ip_in_malicious_subnet"]
            )
            
            severity = predict_severity(
                cvss_score=cvss_score or 5.0,
                feed_confidence=enrichment["feed_confidence"],
                source_count=enrichment["source_count"],
                days_active=enrichment["days_active"],
                ip_in_malicious_subnet=enrichment["ip_in_malicious_subnet"],
                ioc_type=ioc_type
            )
            
            cluster_id, campaign_name = assign_campaign_cluster(
                risk_score=risk_score,
                cvss_score=cvss_score or 5.0,
                feed_confidence=enrichment["feed_confidence"]
            )
            
            stix = generate_stix_indicator(val, ioc_type)
            
            doc = {
                "_id": stix.id,
                "value": val,
                "ioc_type": ioc_type,
                "source": f"Log Upload ({log_type})",
                "description": desc,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "severity": severity,
                "risk_score": risk_score,
                "feed_confidence": enrichment["feed_confidence"],
                "source_count": enrichment["source_count"],
                "days_active": enrichment["days_active"],
                "ip_in_malicious_subnet": enrichment["ip_in_malicious_subnet"],
                "status": "active",
                "mitre_techniques": enrichment["mitre_techniques"],
                "associated_malware": all_malware,
                "associated_cves": all_cves,
                "cvss_score": cvss_score,
                "campaign_id": campaign_name if cluster_id != -1 else None,
                "stix_representation": stix.dict()
            }
            
            await indicators_collection.insert_one(doc)
            imported_count += 1
            
            # Fire critical alert if threat risk >= 80.0
            if risk_score >= 80.0:
                alert_id = f"alert--{str(uuid.uuid4())[:8]}"
                alert_doc = {
                    "_id": alert_id,
                    "indicator_value": val,
                    "ioc_type": ioc_type,
                    "severity": severity,
                    "risk_score": risk_score,
                    "trigger_reason": f"High risk indicator extracted during file upload: {filename}",
                    "status": "Unassigned",
                    "assigned_to": None,
                    "created_at": datetime.utcnow(),
                    "resolved_at": None,
                    "resolution_notes": None
                }
                await alerts_collection.insert_one(alert_doc)
                alert_count += 1
                
        # Log Audit
        await log_audit_action(current_user["username"], current_user["role"], "INDICATORS_BULK_UPLOAD", filename, f"SUCCESS (Imported: {imported_count}, Dups: {duplicate_count})", request)
        cache_store.invalidate("dashboard_metrics")
        
        return {
            "filename": filename,
            "log_type": log_type,
            "status": "processed",
            "extracted_iocs": len(parsed_iocs),
            "imported_count": imported_count,
            "duplicate_count": duplicate_count,
            "alerts_triggered": alert_count
        }
    finally:
        shutil.rmtree(temp_dir)
