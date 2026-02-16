from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Mobile Threat Defense API"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = "postgresql://mtd_user:mtd_password@localhost:5432/mtd_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "CHANGE_THIS_SECRET_KEY_IN_PRODUCTION"
    
    class Config:
        case_sensitive = True

settings = Settings()
