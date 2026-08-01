import asyncio
import logging
import random
from datetime import datetime
from app.database import indicators_collection, alerts_collection, feeds_collection
from app.services.normalization import generate_stix_indicator
from app.services.enrichment import enrich_ioc
from app.services.ml_pipeline import predict_risk_score, predict_severity, assign_campaign_cluster
from app.services.cache_manager import cache_store

logger = logging.getLogger(__name__)

# Sample indicator pools for simulator
SIMULATED_IPS = [
    "185.220.101.4", "45.143.203.14", "91.240.118.220", "193.142.146.211", "5.188.62.74",
    "103.150.186.20", "194.26.29.123", "80.94.95.120", "23.227.198.204", "185.156.74.55",
    "141.98.80.20", "45.9.150.144", "193.233.20.11", "89.248.167.141", "77.247.110.15"
]

SIMULATED_DOMAINS = [
    "paypal-login-security.com", "update-microsoft-support.net", "dhl-tracking-parcel.org",
    "bank-of-america-verify.com", "free-vpn-service.co", "secure-metamask-wallet.io",
    "gdrive-shared-doc.xyz", "admin-panel-portal.pw", "blockchain-ledger-update.info",
    "support-apple-id.cc"
]

SIMULATED_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e", "094fd32504c52c5c56784d12c5b367d0", "c3499c2729730a7f807efb8676a92dcb",
    "5e83f58e7f12e8b2b1154c1d2e2a488e", "8c7ddc522b101c5123d46a8b7c89f5bc", "2f91a56f082e666a7bcf1489069d2de6",
    "a12be40798ff1f66c98aa2b9d997cfba", "f4028bc1b29a2bc1d279cfba7b4d9943", "074df3b4d45c6cf1f4094a974b7029de",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
]

SIMULATED_URLS = [
    "http://paypal-login-security.com/login.php", "https://update-microsoft-support.net/agent.exe",
    "http://dhl-tracking-parcel.org/delivery/invoice.zip", "https://gdrive-shared-doc.xyz/download/doc.pdf",
    "http://secure-metamask-wallet.io/seed.html"
]

harvester_task = None
is_running = False

async def harvest_single_feed(feed_name: str) -> int:
    """
    Simulates harvesting indicators from a specific feed, enriching them, 
    running the ML pipeline, and storing them in MongoDB.
    """
    logger.info(f"Harvesting feed: {feed_name}...")
    
    # Select randomly from the simulated pools
    ioc_type = random.choice(["ip", "domain", "hash", "url"])
    if ioc_type == "ip":
        val = random.choice(SIMULATED_IPS)
    elif ioc_type == "domain":
        val = random.choice(SIMULATED_DOMAINS)
    elif ioc_type == "hash":
        val = random.choice(SIMULATED_HASHES)
    else:
        val = random.choice(SIMULATED_URLS)
        
    # Check if indicator already exists to avoid redundant processing
    existing = await indicators_collection.find_one({"value": val})
    if existing:
        logger.info(f"Indicator {val} already exists in database. Skipping.")
        return 0
        
    # Enrich details
    enrichment = await enrich_ioc(val, ioc_type)
    
    # Calculate ML Risk score and Severity
    risk_score = predict_risk_score(
        cvss_score=enrichment["cvss_score"] or 5.0,
        feed_confidence=enrichment["feed_confidence"],
        source_count=enrichment["source_count"],
        days_active=enrichment["days_active"],
        ip_in_malicious_subnet=enrichment["ip_in_malicious_subnet"]
    )
    
    severity = predict_severity(
        cvss_score=enrichment["cvss_score"] or 5.0,
        feed_confidence=enrichment["feed_confidence"],
        source_count=enrichment["source_count"],
        days_active=enrichment["days_active"],
        ip_in_malicious_subnet=enrichment["ip_in_malicious_subnet"],
        ioc_type=ioc_type
    )
    
    # Assign campaign cluster via DBSCAN distance
    cluster_id, campaign_name = assign_campaign_cluster(
        risk_score=risk_score,
        cvss_score=enrichment["cvss_score"] or 5.0,
        feed_confidence=enrichment["feed_confidence"]
    )
    
    # Create STIX representation
    stix = generate_stix_indicator(val, ioc_type)
    
    doc = {
        "_id": stix.id,
        "value": val,
        "ioc_type": ioc_type,
        "source": feed_name,
        "description": f"Aggregated threat intel from {feed_name} feed.",
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
        "associated_malware": enrichment["associated_malware"],
        "associated_cves": enrichment["associated_cves"],
        "cvss_score": enrichment["cvss_score"],
        "campaign_id": campaign_name if cluster_id != -1 else None,
        "stix_representation": stix.dict()
    }
    
    await indicators_collection.insert_one(doc)
    
    # Update Feed meta
    await feeds_collection.update_one(
        {"name": feed_name},
        {
            "$set": {"last_harvested": datetime.utcnow(), "status": "active"},
            "$inc": {"indicators_count": 1}
        },
        upsert=True
    )
    cache_store.invalidate("dashboard_metrics")
    
    # Raise alert if Risk Score > 80 (Critical alert trigger)
    if risk_score >= 80.0:
        alert_id = f"alert--{str(random.randint(100000, 999999))}"
        alert_doc = {
            "_id": alert_id,
            "indicator_value": val,
            "ioc_type": ioc_type,
            "severity": severity,
            "risk_score": risk_score,
            "trigger_reason": f"High risk threat index of {risk_score:.1f} detected on feed: {feed_name}",
            "status": "Unassigned",
            "assigned_to": None,
            "created_at": datetime.utcnow(),
            "resolved_at": None,
            "resolution_notes": None
        }
        await alerts_collection.insert_one(alert_doc)
        logger.info(f"[ALERT] Critical Threat Alert registered for {val} (Risk Score: {risk_score:.1f})")
        
    return 1

async def harvest_loop():
    """
    Main async polling loop running every 60 seconds to simulate constant threat feed ingestion.
    """
    global is_running
    is_running = True
    feeds = ["AbuseIPDB", "AlienVault OTX", "URLhaus", "MalwareBazaar", "ThreatFox"]
    
    # Initialize feed metadata in DB
    for feed in feeds:
        await feeds_collection.update_one(
            {"name": feed},
            {"$setOnInsert": {"url": f"https://api.simulated.{feed.lower().replace(' ', '')}.com/v1", "indicators_count": 0, "status": "active"}},
            upsert=True
        )
        
    logger.info("Background threat harvesting scheduler started.")
    
    try:
        while is_running:
            # Harvest a random feed
            feed = random.choice(feeds)
            try:
                await harvest_single_feed(feed)
            except Exception as e:
                logger.error(f"Error harvesting feed {feed}: {str(e)}")
            await asyncio.sleep(60)
    except asyncio.CancelledError:
        logger.info("Harvester background task cancelled.")
    finally:
        is_running = False

def start_harvester():
    global harvester_task
    harvester_task = asyncio.create_task(harvest_loop())

def stop_harvester():
    global harvester_task, is_running
    is_running = False
    if harvester_task:
        harvester_task.cancel()
