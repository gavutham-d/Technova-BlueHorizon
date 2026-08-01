import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "threatfusion")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-jwt-key-threat-fusion-soc-2026")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    
    # API Keys for Enrichment
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_OTX_API_KEY: str = os.getenv("ALIENVAULT_OTX_API_KEY", "")
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")
    MALWAREBAZAAR_API_KEY: str = os.getenv("MALWAREBAZAAR_API_KEY", "")
    THREATFOX_API_KEY: str = os.getenv("THREATFOX_API_KEY", "")

    class Config:
        env_file = ".env"

settings = Settings()
