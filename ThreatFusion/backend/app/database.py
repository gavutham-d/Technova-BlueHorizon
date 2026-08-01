from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings
import logging

logger = logging.getLogger(__name__)

client = None
db = None

class CollectionProxy:
    def __init__(self, collection_name: str):
        self._collection_name = collection_name

    def _get_collection(self):
        global db
        if db is None:
            raise RuntimeError("Database not initialized")
        return db[self._collection_name]

    def __getattr__(self, name):
        return getattr(self._get_collection(), name)

# Collection proxies
users_collection = CollectionProxy("users")
indicators_collection = CollectionProxy("indicators")
feeds_collection = CollectionProxy("feeds")
campaigns_collection = CollectionProxy("campaigns")
malware_collection = CollectionProxy("malware")
scores_collection = CollectionProxy("scores")
alerts_collection = CollectionProxy("alerts")
audit_logs_collection = CollectionProxy("audit_logs")

async def init_db():
    global client, db
    
    logger.info(f"Connecting to MongoDB at {settings.MONGODB_URL}")
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.DATABASE_NAME]
    
    # Setup Indexes
    await users_collection.create_index("username", unique=True)
    await indicators_collection.create_index("value", unique=True)
    await indicators_collection.create_index("ioc_type")
    await indicators_collection.create_index("severity")
    await indicators_collection.create_index("risk_score")
    await alerts_collection.create_index("status")
    await audit_logs_collection.create_index("timestamp")
    
    logger.info("MongoDB database collections and indexes initialized successfully.")

async def close_db():
    global client
    if client:
        client.close()
        logger.info("MongoDB connection closed.")

