from fastapi import FastAPI, Depends, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db, close_db, indicators_collection, audit_logs_collection, feeds_collection, users_collection
from app.api import auth, indicators, campaigns, alerts, hunting, reports
from app.services.cti_harvester import start_harvester, stop_harvester, harvest_single_feed
from app.services.ml_pipeline import initialize_ml_models, retrain_pipeline_with_data, generate_synthetic_threat_data
from app.api.auth import RoleChecker, log_audit_action
from app.models.schemas import UserRole
import logging
import asyncio
from datetime import datetime
from starlette.middleware.gzip import GZipMiddleware
from app.services.cache_manager import cache_store

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("threatfusion")

app = FastAPI(
    title="Threat Fusion API",
    description="Cyber Threat Intelligence Aggregation Platform with AI-Powered Threat Hunting",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In development/hackathon allow all or restrict to localhost
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip Compression Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Root status
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Threat Fusion Engine",
        "timestamp": datetime.utcnow().isoformat()
    }

# Retraining and Settings router
settings_router = APIRouter(prefix="/settings", tags=["Settings"])

@settings_router.post("/retrain")
async def trigger_ml_retrain(request: Request, current_user: dict = Depends(RoleChecker([UserRole.ADMIN]))):
    """
    Admin-only trigger to retrain machine learning classifiers on database records.
    """
    logger.info("Triggering ML pipeline retraining...")
    indicators = await indicators_collection.find({}).to_list(length=1000)
    audit_logs = await audit_logs_collection.find({}).to_list(length=1000)
    
    retrain_pipeline_with_data(indicators, audit_logs)
    
    await log_audit_action(current_user["username"], current_user["role"], "ML_PIPELINE_RETRAIN", "all_models", "SUCCESS", request)
    return {"status": "success", "message": "All ML models retrained successfully."}

@settings_router.post("/harvest")
async def trigger_manual_harvest(request: Request, current_user: dict = Depends(RoleChecker([UserRole.ADMIN, UserRole.ANALYST]))):
    """
    Manually triggers harvesting of all threat feeds immediately.
    """
    feeds = ["AbuseIPDB", "AlienVault OTX", "URLhaus", "MalwareBazaar", "ThreatFox"]
    
    # Harvest feeds concurrently
    results = await asyncio.gather(*[harvest_single_feed(feed) for feed in feeds], return_exceptions=True)
    
    count = 0
    for idx, res in enumerate(results):
        if isinstance(res, Exception):
            logger.error(f"Manual harvest failed for {feeds[idx]}: {str(res)}")
        elif isinstance(res, int):
            count += res
            
    cache_store.invalidate("dashboard_metrics")
    await log_audit_action(current_user["username"], current_user["role"], "MANUAL_HARVEST_TRIGGER", "all_feeds", f"SUCCESS - Ingested: {count}", request)
    return {"status": "success", "harvested_count": count}

# Mount routers
app.include_router(auth.router, prefix="/api")
app.include_router(indicators.router, prefix="/api")
app.include_router(campaigns.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(hunting.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(settings_router, prefix="/api")

async def populate_seed_iocs():
    """
    Populates database with initial indicators on first run if database is empty.
    """
    count = await indicators_collection.count_documents({})
    if count == 0:
        logger.info("Populating MongoDB with initial threat indicators for demo...")
        df_seeds = generate_synthetic_threat_data(40)
        
        from app.services.normalization import generate_stix_indicator
        from app.services.enrichment import get_mitre_techniques
        import uuid
        
        feeds = ["AbuseIPDB", "AlienVault OTX", "URLhaus", "MalwareBazaar", "ThreatFox"]
        
        # Insert a default Admin user so they can log in instantly
        # admin/admin123
        from app.api.auth import get_password_hash
        admin_user = await users_collection.find_one({"username": "admin"})
        if not admin_user:
            await users_collection.insert_one({
                "_id": "user--admin-root-0000",
                "username": "admin",
                "email": "admin@threatfusion.local",
                "hashed_password": get_password_hash("admin123"),
                "role": UserRole.ADMIN,
                "created_at": datetime.utcnow()
            })
            logger.info("Default administrator account created: admin / admin123")
            
        for idx, row in df_seeds.iterrows():
            ioc_type = ["ip", "domain", "hash", "url"][int(row["ioc_type_encoded"])]
            
            # Form values
            if ioc_type == "ip":
                val = f"185.220.101.{idx + 10}"
                desc = "TOR exit node or scanner IP"
            elif ioc_type == "domain":
                val = f"phishing-campaign-domain-{idx}.net"
                desc = "Suspicious domain targeting active campaigns"
            elif ioc_type == "hash":
                idx_str = str(idx)
                val = f"d41d8cd98f00b204e9800998ecf8427e"[:-len(idx_str)] + idx_str
                desc = "Malicious executable binary hash"
            else:
                val = f"http://malware-download-server-{idx}.org/payload.exe"
                desc = "Phishing URL containing downloader link"
                
            stix = generate_stix_indicator(val, ioc_type)
            
            # Map DBSCAN Campaign Clusts
            from app.services.ml_pipeline import assign_campaign_cluster
            cluster_id, campaign_name = assign_campaign_cluster(
                risk_score=row["risk_score"],
                cvss_score=row["cvss_score"],
                feed_confidence=row["feed_confidence"]
            )
            
            severity_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
            severity = severity_map.get(int(row["severity"]), "Low")
            
            doc = {
                "_id": stix.id,
                "value": val,
                "ioc_type": ioc_type,
                "source": feeds[idx % len(feeds)],
                "description": desc,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "severity": severity,
                "risk_score": float(row["risk_score"]),
                "feed_confidence": float(row["feed_confidence"]),
                "source_count": int(row["source_count"]),
                "days_active": int(row["days_active"]),
                "ip_in_malicious_subnet": bool(row["ip_in_malicious_subnet"]),
                "status": "active",
                "mitre_techniques": get_mitre_techniques(ioc_type, val),
                "associated_malware": ["Cobalt Strike"] if idx % 3 == 0 else ["LockBit"] if idx % 4 == 0 else ["Adware.Suspicious"],
                "associated_cves": ["CVE-2021-44228"] if idx % 5 == 0 else [],
                "cvss_score": 10.0 if idx % 5 == 0 else None,
                "campaign_id": campaign_name if cluster_id != -1 else None,
                "stix_representation": stix.dict()
            }
            await indicators_collection.insert_one(doc)
            
        logger.info(f"Database populated with {len(df_seeds)} default threat records.")

@app.on_event("startup")
async def startup_event():
    # Connect database
    await init_db()
    # Pre-train ML models
    initialize_ml_models()
    # Setup seed indicators for immediate presentation
    await populate_seed_iocs()
    # Start polling feeds
    start_harvester()
    logger.info("Threat Fusion API startup checks completed.")

@app.on_event("shutdown")
async def shutdown_event():
    stop_harvester()
    await close_db()
    logger.info("Threat Fusion API shutdown completed.")
