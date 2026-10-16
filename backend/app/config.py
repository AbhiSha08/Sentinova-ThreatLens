from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Application ────────────────────────────────────────────────────────────
    PROJECT_NAME: str = "ThreatLens CTI Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # ── Database ───────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite:///./threatlens.db"

    # ── Redis ──────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Threat Intelligence Feed URLs ──────────────────────────────────────────
    CISA_KEV_URL: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    URLHAUS_RECENT_URL: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    # ── API Keys ───────────────────────────────────────────────────────────────
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""


settings = Settings()
