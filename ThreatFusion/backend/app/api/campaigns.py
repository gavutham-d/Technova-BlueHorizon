from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from app.database import indicators_collection, campaigns_collection
from app.models.schemas import CampaignSchema, UserRole
from app.api.auth import get_current_user, RoleChecker
from datetime import datetime
import uuid

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])

read_guard = RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.READ_ONLY])

@router.get("", response_model=List[Dict[str, Any]])
async def list_campaigns(current_user: dict = Depends(read_guard)):
    """
    Returns campaigns and summaries of their indicators.
    """
    # Group indicators by campaign_id
    pipeline = [
        {"$match": {"campaign_id": {"$ne": None}}},
        {
            "$group": {
                "_id": "$campaign_id",
                "indicators_count": {"$sum": 1},
                "max_risk_score": {"$max": "$risk_score"},
                "malware_tags": {"$addToSet": "$associated_malware"},
                "types": {"$addToSet": "$ioc_type"}
            }
        }
    ]
    
    cursor = indicators_collection.aggregate(pipeline)
    aggregations = await cursor.to_list(length=100)
    
    campaigns = []
    for agg in aggregations:
        # Flatten malware tags list of lists
        flat_malware = list(set([m for sublist in agg["malware_tags"] for m in sublist if m]))
        campaigns.append({
            "name": agg["_id"],
            "indicators_count": agg["indicators_count"],
            "max_risk_score": round(agg["max_risk_score"], 1),
            "malware_tags": flat_malware,
            "ioc_types": agg["types"],
            "threat_actor": "APT Group" if "APT" in agg["_id"] or "Simulated" in agg["_id"] else "Financially Motivated Cybercriminals"
        })
        
    # If no campaign exists yet, return simulated ones to display
    if not campaigns:
        campaigns = [
            {
                "name": "Operation CyberShield (APT-39 Simulated)",
                "indicators_count": 8,
                "max_risk_score": 92.4,
                "malware_tags": ["Cobalt Strike", "NjRAT"],
                "ioc_types": ["ip", "domain"],
                "threat_actor": "APT-39"
            },
            {
                "name": "LockBit 4.0 Campaign Group",
                "indicators_count": 12,
                "max_risk_score": 88.1,
                "malware_tags": ["LockBit"],
                "ioc_types": ["ip", "hash"],
                "threat_actor": "LockBit Affiliate"
            }
        ]
        
    return campaigns

@router.get("/graph")
async def get_campaign_graph(current_user: dict = Depends(read_guard)):
    """
    Returns nodes and edges representing the relationships between campaigns, indicators, and malware.
    Useful for cytoscape/force-directed graph renderings.
    """
    cursor = indicators_collection.find({"campaign_id": {"$ne": None}}).limit(100)
    indicators = await cursor.to_list(length=100)
    
    nodes = []
    edges = []
    
    # Track items to prevent duplicate nodes
    added_nodes = set()
    
    for ind in indicators:
        val = ind["value"]
        camp_id = ind["campaign_id"]
        
        # 1. Add Campaign Node
        if camp_id not in added_nodes:
            nodes.append({
                "id": camp_id,
                "label": camp_id,
                "type": "campaign",
                "size": 30,
                "color": "#a855f7" # purple
            })
            added_nodes.add(camp_id)
            
        # 2. Add Indicator Node
        if val not in added_nodes:
            nodes.append({
                "id": val,
                "label": val,
                "type": "indicator",
                "ioc_type": ind["ioc_type"],
                "risk_score": ind["risk_score"],
                "severity": ind["severity"],
                "size": 15 + int(ind["risk_score"] / 10),
                "color": "#06b6d4" if ind["ioc_type"] == "ip" else "#3b82f6" # cyan/blue
            })
            added_nodes.add(val)
            
        # Add Edge Campaign -> Indicator
        edges.append({
            "id": f"edge--{camp_id}--{val}",
            "source": camp_id,
            "target": val,
            "label": "contains"
        })
        
        # 3. Add Malware Nodes and Edges
        for mal in ind.get("associated_malware", []):
            if not mal or mal == "Unknown Agent":
                continue
            if mal not in added_nodes:
                nodes.append({
                    "id": mal,
                    "label": mal,
                    "type": "malware",
                    "size": 22,
                    "color": "#ef4444" # red
                })
                added_nodes.add(mal)
                
            edges.append({
                "id": f"edge--{val}--{mal}",
                "source": val,
                "target": mal,
                "label": "uses"
            })
            
    # Default visual nodes if database is empty
    if not nodes:
        nodes = [
            {"id": "Operation CyberShield", "label": "Operation CyberShield", "type": "campaign", "size": 30, "color": "#a855f7"},
            {"id": "185.220.101.4", "label": "185.220.101.4", "type": "indicator", "ioc_type": "ip", "risk_score": 92.4, "severity": "Critical", "size": 24, "color": "#06b6d4"},
            {"id": "update-microsoft-support.net", "label": "update-microsoft-support.net", "type": "indicator", "ioc_type": "domain", "risk_score": 75.0, "severity": "High", "size": 22, "color": "#3b82f6"},
            {"id": "Cobalt Strike", "label": "Cobalt Strike", "type": "malware", "size": 22, "color": "#ef4444"}
        ]
        edges = [
            {"id": "e1", "source": "Operation CyberShield", "target": "185.220.101.4", "label": "contains"},
            {"id": "e2", "source": "Operation CyberShield", "target": "update-microsoft-support.net", "label": "contains"},
            {"id": "e3", "source": "185.220.101.4", "target": "Cobalt Strike", "label": "uses"},
            {"id": "e4", "source": "update-microsoft-support.net", "target": "Cobalt Strike", "label": "uses"}
        ]
        
    return {"nodes": nodes, "edges": edges}
