from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Dict, Any, Optional
from app.database import alerts_collection
from app.models.schemas import AlertSchema, UserRole
from app.api.auth import get_current_user, RoleChecker, log_audit_action
from datetime import datetime
from app.services.cache_manager import cache_store

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# Analysts and Admins can manage incidents
write_guard = RoleChecker([UserRole.ADMIN, UserRole.ANALYST])
read_guard = RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.READ_ONLY])

@router.get("", response_model=List[AlertSchema])
async def list_alerts(
    status_filter: Optional[str] = None,
    current_user: dict = Depends(read_guard)
):
    query = {}
    if status_filter:
        query["status"] = status_filter
        
    cursor = alerts_collection.find(query).sort("created_at", -1)
    results = await cursor.to_list(length=100)
    return results

@router.post("/{id}/assign")
async def assign_alert(
    id: str,
    request: Request,
    assigned_to: Optional[str] = None,
    current_user: dict = Depends(write_guard)
):
    alert = await alerts_collection.find_one({"_id": id})
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_BAD_REQUEST, detail="Alert incident not found.")
        
    assignee = assigned_to or current_user["username"]
    
    await alerts_collection.update_one(
        {"_id": id},
        {
            "$set": {
                "status": "Assigned",
                "assigned_to": assignee
            }
        }
    )
    cache_store.invalidate("dashboard_metrics")
    
    await log_audit_action(current_user["username"], current_user["role"], "ALERT_ASSIGN", f"{id} -> {assignee}", "SUCCESS", request)
    return {"status": "assigned", "assigned_to": assignee}

@router.post("/{id}/resolve")
async def resolve_alert(
    id: str,
    request: Request,
    notes: str = "Resolved during standard analyst triage.",
    current_user: dict = Depends(write_guard)
):
    alert = await alerts_collection.find_one({"_id": id})
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_BAD_REQUEST, detail="Alert incident not found.")
        
    await alerts_collection.update_one(
        {"_id": id},
        {
            "$set": {
                "status": "Resolved",
                "resolved_at": datetime.utcnow(),
                "resolution_notes": notes
            }
        }
    )
    cache_store.invalidate("dashboard_metrics")
    
    await log_audit_action(current_user["username"], current_user["role"], "ALERT_RESOLVE", id, "SUCCESS", request)
    return {"status": "resolved", "resolved_at": datetime.utcnow()}
