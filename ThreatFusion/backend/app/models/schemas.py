from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime

# --- USER AUTHENTICATION & ZERO TRUST SYSTEM ---
class UserRole:
    ADMIN = "Admin"
    ANALYST = "Analyst"
    READ_ONLY = "Read-Only"

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: str = Field(default=UserRole.READ_ONLY)

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: str = Field(..., alias="_id")
    username: str
    email: str
    role: str
    created_at: datetime

    class Config:
        populate_by_name = True
        json_encoders = {datetime: lambda v: v.isoformat()}

class UserInDB(BaseModel):
    username: str
    email: str
    hashed_password: str
    role: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


# --- STIX 2.1 INDICATOR & METADATA ENRICHMENT ---
class STIX21Indicator(BaseModel):
    id: str
    type: str = "indicator"
    spec_version: str = "2.1"
    pattern: str
    pattern_type: str = "stix"
    valid_from: str
    created: str
    modified: str
    labels: List[str] = []
    indicator_types: List[str] = []

class IndicatorCreate(BaseModel):
    value: str
    ioc_type: str  # ip, domain, hash, url
    source: str = "Manual Upload"
    description: Optional[str] = None
    associated_cves: List[str] = []
    associated_malware: List[str] = []

class IndicatorResponse(BaseModel):
    id: str = Field(..., alias="_id")
    value: str
    ioc_type: str
    source: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    # Enrichment fields
    severity: str = "Low"  # Low, Medium, High, Critical
    risk_score: float = 0.0  # 0 to 100
    feed_confidence: float = 80.0
    source_count: int = 1
    days_active: int = 1
    ip_in_malicious_subnet: bool = False
    status: str = "active"  # active, stale
    
    # Threat Intelligence Connections
    mitre_techniques: List[str] = []
    associated_malware: List[str] = []
    associated_cves: List[str] = []
    cvss_score: Optional[float] = None
    campaign_id: Optional[str] = None
    
    # STIX representation
    stix_representation: Optional[STIX21Indicator] = None

    class Config:
        populate_by_name = True
        json_encoders = {datetime: lambda v: v.isoformat()}


# --- OTHER COLLECTIONS ---
class ThreatFeedSchema(BaseModel):
    id: str = Field(..., alias="_id")
    name: str
    url: str
    last_harvested: Optional[datetime] = None
    status: str = "active"  # active, offline
    indicators_count: int = 0

    class Config:
        populate_by_name = True

class CampaignSchema(BaseModel):
    id: str = Field(..., alias="_id")
    name: str
    cluster_id: int
    threat_actor: Optional[str] = None
    malware_tags: List[str] = []
    indicators: List[str] = []  # List of Indicator values
    created_at: datetime

    class Config:
        populate_by_name = True

class AlertSchema(BaseModel):
    id: str = Field(..., alias="_id")
    indicator_value: str
    ioc_type: str
    severity: str
    risk_score: float
    trigger_reason: str
    status: str = "Unassigned"  # Unassigned, Assigned, Investigating, Resolved
    assigned_to: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None

    class Config:
        populate_by_name = True

class AuditLogSchema(BaseModel):
    id: str = Field(..., alias="_id")
    username: str
    role: str
    action: str  # e.g., "USER_LOGIN", "INDICATOR_DELETE", "ALERT_RESOLVE"
    resource: str
    status: str  # SUCCESS, FAILED
    ip_address: str
    timestamp: datetime

    class Config:
        populate_by_name = True
